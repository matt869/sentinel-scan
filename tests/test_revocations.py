"""Tests for the rule revocation kill switch.

The property every test here defends: a revocation can only ever *remove* a
detection, and anything that goes wrong with the list leaves every rule
active. A kill switch that fails closed silently disables the scanner, which
is worse than the bad rule it exists to turn off.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.config import Config
from sentinel.engine.verdict import Detection
from sentinel.signatures.revocations import (
    MAX_REVOCATIONS,
    REVOCATION_FILENAME,
    Revocation,
    RevocationList,
)
from sentinel.signatures.updater import SignatureUpdater

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def detection(
    name: str = "Bad_Rule",
    detector: str = "yara",
    confidence: float = 80.0,
    conclusive: bool = False,
    **metadata: Any,
) -> Detection:
    return Detection(
        detector=detector,
        name=name,
        confidence=confidence,
        conclusive=conclusive,
        metadata=metadata,
    )


def write_list(config: Config, payload: Any) -> Path:
    """Install a revocation list for *config* and return its path."""
    path = Path(config.paths.signatures_dir) / REVOCATION_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ----------------------------------------------------------------------
# parsing
# ----------------------------------------------------------------------

class TestParsing:
    def test_full_entry(self) -> None:
        revocations = RevocationList.from_dict(
            {
                "version": 3,
                "revoked": [
                    {
                        "rule": "Suspicious_Base64",
                        "detector": "yara",
                        "reason": "fires on Windows Update scripts",
                    }
                ],
            }
        )
        assert len(revocations) == 1
        assert revocations.version == "3"
        assert revocations.is_revoked(detection("Suspicious_Base64"))

    def test_bare_string_list(self) -> None:
        # Most revocations need nothing but a name.
        revocations = RevocationList.from_dict(["Bad_Rule", "Worse_Rule"])
        assert len(revocations) == 2
        assert revocations.is_revoked(detection("Bad_Rule"))

    def test_matching_is_case_insensitive(self) -> None:
        revocations = RevocationList.from_dict(["bad_RULE"])
        assert revocations.is_revoked(detection("BAD_rule"))

    def test_entry_without_a_rule_name_is_dropped(self) -> None:
        revocations = RevocationList.from_dict({"revoked": [{"reason": "oops"}, 42, None]})
        assert len(revocations) == 0

    def test_wildcards_are_refused(self) -> None:
        # "Disable everything matching Trojan.*" is not a switch anyone should
        # be able to flip remotely.
        revocations = RevocationList.from_dict(["Trojan.*", "Emotet_?"])
        assert len(revocations) == 0

    def test_oversized_list_is_rejected_entirely(self) -> None:
        # A list wanting to disable everything is a mistake or an attack, and
        # the safe response is to keep every rule active.
        payload = [f"Rule_{i}" for i in range(MAX_REVOCATIONS + 1)]
        revocations = RevocationList.from_dict(payload)
        assert len(revocations) == 0

    @pytest.mark.parametrize("payload", ["a string", 42, None, {"revoked": "nope"}])
    def test_malformed_payloads_revoke_nothing(self, payload: Any) -> None:
        assert len(RevocationList.from_dict(payload)) == 0


# ----------------------------------------------------------------------
# expiry
# ----------------------------------------------------------------------

class TestExpiry:
    def test_expired_revocation_lapses(self) -> None:
        revocations = RevocationList.from_dict(
            {"revoked": [{"rule": "Old_Rule", "expires": "2020-01-01"}]},
            today=date(2026, 8, 3),
        )
        assert len(revocations) == 0
        assert not revocations.is_revoked(detection("Old_Rule"))

    def test_future_expiry_still_applies(self) -> None:
        revocations = RevocationList.from_dict(
            {"revoked": [{"rule": "Current", "expires": "2030-01-01"}]},
            today=date(2026, 8, 3),
        )
        assert revocations.is_revoked(detection("Current"))

    def test_expiring_today_still_applies(self) -> None:
        revocations = RevocationList.from_dict(
            {"revoked": [{"rule": "Current", "expires": "2026-08-03"}]},
            today=date(2026, 8, 3),
        )
        assert revocations.is_revoked(detection("Current"))

    def test_unreadable_expiry_keeps_the_rule_disabled(self) -> None:
        # A typo in a date is not evidence that the reason for revoking went
        # away, so the revocation stands.
        revocations = RevocationList.from_dict(
            {"revoked": [{"rule": "Broken", "expires": "next tuesday"}]},
            today=date(2026, 8, 3),
        )
        assert revocations.is_revoked(detection("Broken"))

    def test_no_expiry_is_permanent(self) -> None:
        assert Revocation(rule="x").active_on(date(2099, 1, 1))


# ----------------------------------------------------------------------
# matching
# ----------------------------------------------------------------------

class TestMatching:
    def test_matches_the_rule_recorded_in_metadata(self) -> None:
        # YARA reports the threat name but records the rule that matched.
        revocations = RevocationList.from_dict(["Packer_Generic"])
        hit = detection(name="Trojan.Packed", rule="Packer_Generic")
        assert revocations.is_revoked(hit)

    def test_detector_scope_limits_the_revocation(self) -> None:
        revocations = RevocationList.from_dict(
            [{"rule": "Shared_Name", "detector": "yara"}]
        )
        assert revocations.is_revoked(detection("Shared_Name", detector="yara"))
        assert not revocations.is_revoked(detection("Shared_Name", detector="script"))

    def test_no_detector_scope_matches_any_detector(self) -> None:
        revocations = RevocationList.from_dict(["Shared_Name"])
        assert revocations.is_revoked(detection("Shared_Name", detector="script"))
        assert revocations.is_revoked(detection("Shared_Name", detector="pe_heuristic"))

    def test_unrelated_detections_are_untouched(self) -> None:
        revocations = RevocationList.from_dict(["Bad_Rule"])
        assert not revocations.is_revoked(detection("Good_Rule"))

    def test_find_returns_the_reason(self) -> None:
        revocations = RevocationList.from_dict(
            [{"rule": "Bad_Rule", "reason": "matches every installer"}]
        )
        found = revocations.find(detection("Bad_Rule"))
        assert found is not None
        assert found.reason == "matches every installer"


# ----------------------------------------------------------------------
# filtering
# ----------------------------------------------------------------------

class TestFiltering:
    def test_drops_only_the_revoked_detection(self) -> None:
        revocations = RevocationList.from_dict(["Bad_Rule"])
        kept = revocations.filter(
            [detection("Bad_Rule"), detection("Good_Rule"), detection("Other_Rule")]
        )
        assert [d.name for d in kept] == ["Good_Rule", "Other_Rule"]

    def test_empty_list_is_a_passthrough(self) -> None:
        detections = [detection("Anything"), detection("Else")]
        assert RevocationList.empty().filter(detections) == detections

    def test_preserves_order(self) -> None:
        revocations = RevocationList.from_dict(["B"])
        kept = revocations.filter([detection("A"), detection("B"), detection("C")])
        assert [d.name for d in kept] == ["A", "C"]


# ----------------------------------------------------------------------
# loading from disk
# ----------------------------------------------------------------------

class TestLoading:
    def test_loads_the_installed_list(self, config: Config) -> None:
        write_list(config, {"revoked": ["Installed_Rule"]})
        revocations = RevocationList.load(config)
        assert revocations.is_revoked(detection("Installed_Rule"))

    def test_missing_file_revokes_nothing(self, config: Config) -> None:
        assert len(RevocationList.load(config)) == 0

    def test_corrupt_file_fails_open(self, config: Config) -> None:
        path = Path(config.paths.signatures_dir) / REVOCATION_FILENAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{ this is not json", encoding="utf-8")
        # Every rule stays active: a broken kill switch must not disable the
        # scanner.
        assert len(RevocationList.load(config)) == 0

    def test_configuration_can_opt_out(self, config: Config) -> None:
        write_list(config, {"revoked": ["Installed_Rule"]})
        config.updates.honor_revocations = False
        assert len(RevocationList.load(config)) == 0

    def test_no_config_is_safe(self) -> None:
        assert len(RevocationList.load(None)) == 0


# ----------------------------------------------------------------------
# engine integration
# ----------------------------------------------------------------------

class TestScannerIntegration:
    def test_revoked_rule_stops_flagging_the_file(
        self, config: Config, scanner: Any, powershell_dropper: Path
    ) -> None:
        before = scanner.scan_file(powershell_dropper)
        assert before.is_threat
        revoked = {d.name for d in before.detections}

        write_list(config, {"revoked": sorted(revoked)})
        after = scanner.scan_file(powershell_dropper)

        assert not after.detections
        assert after.is_clean

    def test_revoked_conclusive_hit_does_not_short_circuit(
        self, config: Config, scanner: Any, hash_signature_db: Any,
        powershell_dropper: Path,
    ) -> None:
        # A conclusive hash match normally stops the pipeline. If that match
        # is revoked it must not suppress the detectors that would have run
        # after it — otherwise one bad hash entry blinds the whole scanner
        # for that file.
        from sentinel.utils.hashing import hash_file

        hash_signature_db(hash_file(powershell_dropper), "Wrong.Signature", "critical")
        write_list(config, {"revoked": [{"rule": "Wrong.Signature", "detector": "hash"}]})

        verdict = scanner.scan_file(powershell_dropper)

        assert "hash" not in verdict.detector_names
        assert "script" in verdict.detector_names
        assert verdict.is_threat

    def test_revocation_scoped_to_another_detector_is_ignored(
        self, config: Config, scanner: Any, powershell_dropper: Path
    ) -> None:
        before = scanner.scan_file(powershell_dropper)
        names = sorted({d.name for d in before.detections})
        write_list(
            config, {"revoked": [{"rule": name, "detector": "yara"} for name in names]}
        )

        after = scanner.scan_file(powershell_dropper)
        assert after.is_threat


# ----------------------------------------------------------------------
# fetching
# ----------------------------------------------------------------------

class FakeResponse:
    def __init__(self, content: bytes, status: int = 200) -> None:
        self.content = content
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")


class FakeClient:
    """Stands in for httpx.Client, recording the URL it was asked for."""

    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requested: list[str] = []

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def get(self, url: str) -> FakeResponse:
        self.requested.append(url)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def updater(config: Config) -> SignatureUpdater:
    config.updates.mirror_url = "https://mirror.invalid/v1"
    return SignatureUpdater(config)


def serve(
    updater: SignatureUpdater, monkeypatch: pytest.MonkeyPatch,
    body: bytes | Exception,
) -> FakeClient:
    response = body if isinstance(body, Exception) else FakeResponse(body)
    client = FakeClient(response)
    monkeypatch.setattr(updater, "_client", lambda: client)
    return client


class TestFetching:
    def test_installs_the_fetched_list(
        self, updater: SignatureUpdater, config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = serve(
            updater, monkeypatch, json.dumps({"revoked": ["Bad_Rule"]}).encode()
        )

        assert updater.fetch_revocations() == 1
        assert client.requested == [f"https://mirror.invalid/v1/{REVOCATION_FILENAME}"]
        assert RevocationList.load(config).is_revoked(detection("Bad_Rule"))

    def test_network_failure_is_not_fatal(
        self, updater: SignatureUpdater, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        serve(updater, monkeypatch, RuntimeError("mirror unreachable"))
        assert updater.fetch_revocations() == -1

    def test_corrupt_download_keeps_the_installed_copy(
        self, updater: SignatureUpdater, config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        write_list(config, {"revoked": ["Known_Bad_Rule"]})
        serve(updater, monkeypatch, b"{ not json at all")

        assert updater.fetch_revocations() == -1
        # Installing an unparseable list would fail open and silently
        # un-revoke the rule the last good copy had disabled.
        assert RevocationList.load(config).is_revoked(detection("Known_Bad_Rule"))

    def test_oversized_download_is_refused(
        self, updater: SignatureUpdater, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentinel.signatures.updater import MAX_REVOCATION_SIZE

        serve(updater, monkeypatch, b"[" + b'"x",' * MAX_REVOCATION_SIZE + b'"y"]')
        assert updater.fetch_revocations() == -1

    def test_opting_out_skips_the_fetch(
        self, updater: SignatureUpdater, config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        updater.honor_revocations = False
        client = serve(updater, monkeypatch, b'["Bad_Rule"]')

        assert updater.fetch_revocations() == -1
        assert client.requested == []

    def test_explicit_url_overrides_the_mirror(
        self, updater: SignatureUpdater, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        updater.revocation_url = "https://elsewhere.invalid/revoked.json"
        client = serve(updater, monkeypatch, b"[]")

        updater.fetch_revocations()
        assert client.requested == ["https://elsewhere.invalid/revoked.json"]

    def test_background_refresh_runs_once_per_interval(
        self, config: Config, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentinel.signatures import updater as updater_module

        calls: list[int] = []
        monkeypatch.setattr(
            updater_module.SignatureUpdater, "fetch_revocations",
            lambda self: calls.append(1),
        )

        first = updater_module.refresh_revocations_in_background(config, db)
        assert first is not None
        first.join(timeout=5)
        assert len(calls) == 1

        # Second call is inside the interval, so nothing is started: a scan
        # every five minutes must not mean a request every five minutes.
        assert updater_module.refresh_revocations_in_background(config, db) is None
        assert len(calls) == 1

    def test_background_refresh_respects_the_opt_out(
        self, config: Config, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentinel.signatures import updater as updater_module

        monkeypatch.setattr(
            updater_module.SignatureUpdater, "fetch_revocations",
            lambda self: pytest.fail("should not have fetched"),
        )
        config.updates.honor_revocations = False
        assert updater_module.refresh_revocations_in_background(config, db) is None

    def test_background_refresh_survives_a_dead_mirror(
        self, config: Config, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentinel.signatures import updater as updater_module

        def explode(self: Any) -> int:
            raise RuntimeError("mirror on fire")

        monkeypatch.setattr(
            updater_module.SignatureUpdater, "fetch_revocations", explode
        )
        thread = updater_module.refresh_revocations_in_background(config, db)
        assert thread is not None
        thread.join(timeout=5)
        assert not thread.is_alive()

    def test_revocations_land_without_a_version_bump(
        self, updater: SignatureUpdater, config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The whole point of the kill switch: a bad rule is switched off on
        # the next update check, not the next signature release.
        monkeypatch.setattr(
            updater, "_fetch_manifest",
            lambda: {"version": "0", "bundles": []},
        )
        serve(updater, monkeypatch, json.dumps({"revoked": ["Bad_Rule"]}).encode())

        result = updater.update()

        assert not result.updated  # version unchanged
        assert result.revoked_rules == 1
        assert RevocationList.load(config).is_revoked(detection("Bad_Rule"))
