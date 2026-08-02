"""HTTP client for the Sentinel reporting server.

All network access from the client goes through this class, which gives one
place to enforce the rules:

* Nothing is sent unless a server URL is configured.
* Every request carries a timeout. A hung server must never hang a scan.
* Failures raise :class:`ServerError`; callers treat that as "carry on
  offline", never as a fatal condition.
* Retries are limited and only for transient failures. A 4xx is a bug in our
  request, not something to hammer the server about.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from sentinel.core.logger import get_logger
from sentinel.version import USER_AGENT, __version__

log = get_logger(__name__)

#: Status codes worth retrying: transient server-side or rate limiting.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

MAX_RETRIES = 2
BACKOFF_BASE = 0.5


class ServerError(RuntimeError):
    """Raised when the server could not be reached or refused the request."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def is_auth_error(self) -> bool:
        return self.status in (401, 403)


@dataclass(slots=True)
class SubmissionResult:
    """What the server said about a submitted report."""

    accepted: bool
    report_id: str = ""
    message: str = ""
    url: str = ""

    def __str__(self) -> str:
        if self.accepted:
            return f"Report {self.report_id} accepted"
        return self.message or "Report was not accepted"


class ServerClient:
    """Talks to a Sentinel reporting server."""

    def __init__(self, privacy: Any) -> None:
        """
        Args:
            privacy: A :class:`~sentinel.core.config.PrivacySettings`.
        """
        self.base_url = str(getattr(privacy, "server_url", "") or "").rstrip("/")
        self.token = str(getattr(privacy, "api_token", "") or "")
        self.timeout = float(getattr(privacy, "request_timeout", 15.0))
        self._client: Any = None

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    # -- transport -----------------------------------------------------

    def _get_client(self) -> Any:
        if self._client is None:
            import httpx

            headers = {
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "X-Sentinel-Version": __version__,
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self._client = httpx.Client(
                base_url=self.base_url, timeout=self.timeout, headers=headers,
                follow_redirects=False,  # a redirect could leak the token
            )
        return self._client

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """Issue a request, retrying transient failures."""
        if not self.configured:
            raise ServerError("no server configured (privacy.server_url is empty)")

        import httpx

        client = self._get_client()
        last_error = "unknown error"

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = client.request(method, path, **kwargs)
            except httpx.TimeoutException as exc:
                last_error = f"timed out after {self.timeout}s"
                log.debug("%s %s: %s", method, path, last_error)
                if attempt < MAX_RETRIES:
                    time.sleep(BACKOFF_BASE * (2**attempt))
                    continue
                raise ServerError(last_error) from exc
            except httpx.HTTPError as exc:
                last_error = str(exc)
                if attempt < MAX_RETRIES:
                    time.sleep(BACKOFF_BASE * (2**attempt))
                    continue
                raise ServerError(f"cannot reach {self.base_url}: {exc}") from exc

            if response.status_code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                # Honour Retry-After when the server sets it.
                delay = BACKOFF_BASE * (2**attempt)
                header = response.headers.get("retry-after")
                if header and header.isdigit():
                    delay = min(float(header), 30.0)
                log.debug("server returned %d; retrying in %.1fs",
                          response.status_code, delay)
                time.sleep(delay)
                continue

            if response.status_code >= 400:
                raise ServerError(
                    f"server returned {response.status_code}: "
                    f"{_error_detail(response)}",
                    status=response.status_code,
                )

            try:
                data = response.json()
            except ValueError as exc:
                raise ServerError("server returned a non-JSON response") from exc

            return data if isinstance(data, dict) else {"data": data}

        raise ServerError(last_error)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- endpoints -----------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Check the server is alive. Used by ``sentinel report --test``."""
        return self._request("GET", "/health")

    def lookup_hashes(self, digests: list[str]) -> dict[str, dict[str, Any]]:
        """Reputation lookup for a batch of sha256 digests.

        Sends hashes only — never names, paths or contents.

        Returns:
            Mapping of digest to its reputation record. Digests the server
            does not know are simply absent.
        """
        if not digests:
            return {}
        data = self._request("POST", "/v1/hashes/lookup", json={"hashes": digests})
        results = data.get("results", {})
        return results if isinstance(results, dict) else {}

    def submit_report(self, payload: dict[str, Any]) -> SubmissionResult:
        """Submit a false-positive or missed-detection report."""
        data = self._request("POST", "/v1/reports", json=payload)
        return SubmissionResult(
            accepted=bool(data.get("accepted", True)),
            report_id=str(data.get("report_id", "")),
            message=str(data.get("message", "")),
            url=str(data.get("url", "")),
        )

    def upload_sample(
        self, report_id: str, filename: str, content: bytes, content_type: str
    ) -> SubmissionResult:
        """Attach a file to an existing report.

        Only ever called after explicit per-file consent; see
        :mod:`sentinel.feedback.sample_upload`.
        """
        data = self._request(
            "POST",
            f"/v1/reports/{report_id}/sample",
            files={"file": (filename, content, content_type)},
        )
        return SubmissionResult(
            accepted=bool(data.get("accepted", True)),
            report_id=report_id,
            message=str(data.get("message", "")),
        )

    def submit_telemetry(self, payload: dict[str, Any]) -> bool:
        """Send an anonymous counters batch. Returns True if accepted."""
        try:
            self._request("POST", "/v1/telemetry", json=payload)
            return True
        except ServerError as exc:
            log.debug("telemetry rejected: %s", exc)
            return False

    def stats(self) -> dict[str, Any]:
        """Aggregate detection statistics published by the server."""
        return self._request("GET", "/v1/stats")


def _error_detail(response: Any) -> str:
    """Pull a human-readable message out of an error response."""
    try:
        body = response.json()
    except ValueError:
        return (response.text or "")[:200]
    if isinstance(body, dict):
        for key in ("detail", "message", "error"):
            if key in body:
                return str(body[key])[:200]
    return str(body)[:200]
