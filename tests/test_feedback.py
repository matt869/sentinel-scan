"""Tests for the feedback subsystem.

The consent gates are the important part here. A bug that leaks a file the
user did not agree to send cannot be walked back, so these tests assert the
refusals as carefully as the happy paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.engine.verdict import Detection, build_verdict
from sentinel.feedback.github_fallback import (
    MAX_URL_LENGTH,
    build_issue_body,
    build_issue_url,
)
from sentinel.feedback.report import (
    FileFacts,
    Report,
    ReportKind,
    build_false_positive,
    build_missed_detection,
    environment_facts,
    save_local,
    submit,
)
from sentinel.feedback.sample_upload import (
    MAX_SAMPLE_SIZE,
    NEVER_UPLOAD_EXTENSIONS,
    check_sample,
    upload_sample,
)
from sentinel.feedback.telemetry import TelemetryCollector, bucket
from sentinel.utils.hashing import hash_file


@pytest.fixture
def verdict(tmp_path: Path):
    path = tmp_path / "installer.exe"
    path.write_bytes(b"MZ" + b"\x90" * 2048)
    return build_verdict(
        str(path),
        [
            Detection("pe_heuristic", "Heuristic.Packed.UPX", 30, "packed"),
            Detection("yara", "Suspicious.Rule", 55, "matched a rule"),
        ],
        sha256=hash_file(path),
        size=path.stat().st_size,
    )


# ----------------------------------------------------------------------
# report construction
# ----------------------------------------------------------------------

class TestReportBuilding:
    def test_false_positive_carries_the_detections(self, verdict) -> None:
        report = build_false_positive(verdict, "This is my own build output.")
        assert report.kind is ReportKind.FALSE_POSITIVE
        assert len(report.detections) == 2
        assert report.file.sha256 == verdict.sha256

    def test_missed_detection_has_no_detections(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.exe"
        path.write_bytes(b"MZ\x90\x00")
        report = build_missed_detection(path, "This is definitely malware.")
        assert report.kind is ReportKind.MISSED_DETECTION
        assert report.detections == []

    def test_full_path_is_not_included(self, verdict) -> None:
        """The path holds the username and often a client or project name."""
        report = build_false_positive(verdict, "My own build output, safe.")
        payload = report.to_json()
        assert verdict.path not in payload
        assert report.file.name == "installer.exe"

    def test_environment_has_no_identifying_details(self) -> None:
        facts = environment_facts()
        joined = json.dumps(facts).lower()
        import getpass
        import socket

        assert getpass.getuser().lower() not in joined
        assert socket.gethostname().lower() not in joined
        assert set(facts) == {
            "sentinel_version", "python_version", "os", "os_release", "machine",
        }

    def test_validation_requires_an_explanation(self, verdict) -> None:
        report = build_false_positive(verdict, "no")
        problems = report.validate()
        assert any("describe" in p for p in problems)

    def test_validation_requires_detections_for_a_false_positive(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "f.bin"
        path.write_bytes(b"data")
        report = Report(
            kind=ReportKind.FALSE_POSITIVE,
            file=FileFacts.from_path(path),
            comment="This explanation is definitely long enough.",
        )
        assert any("disputes" in p for p in report.validate())

    def test_valid_report_has_no_problems(self, verdict) -> None:
        report = build_false_positive(
            verdict, "This is our signed installer, built in CI."
        )
        assert report.validate() == []

    def test_save_local(self, verdict, config) -> None:
        report = build_false_positive(verdict, "Saving this one to disk.")
        path = save_local(report, config)
        assert path.is_file()
        assert json.loads(path.read_text())["kind"] == "false_positive"


# ----------------------------------------------------------------------
# GitHub fallback
# ----------------------------------------------------------------------

class TestGitHubFallback:
    def test_issue_body_contains_the_facts(self, verdict) -> None:
        report = build_false_positive(verdict, "My own build, safe to run.")
        body = build_issue_body(report)

        assert verdict.sha256 in body
        assert "installer.exe" in body
        assert "Heuristic.Packed.UPX" in body
        assert "My own build, safe to run." in body

    def test_issue_body_omits_the_path(self, verdict) -> None:
        report = build_false_positive(verdict, "My own build, safe to run.")
        assert verdict.path not in build_issue_body(report)

    def test_url_is_well_formed(self, verdict, config) -> None:
        report = build_false_positive(verdict, "My own build, safe to run.")
        url = build_issue_url(report, config)

        assert url.startswith("https://github.com/")
        assert "/issues/new?" in url
        assert "title=" in url and "body=" in url

    def test_oversized_report_falls_back_to_a_file(
        self, verdict, config
    ) -> None:
        """A huge report must not produce a URL browsers will reject.

        The detection table is already bounded (15 rows, truncated
        descriptions), so the realistic way to blow the limit is a very long
        user comment.
        """
        long_comment = (
            "Here is a very detailed explanation of why this file is safe. " * 200
        )
        report = build_false_positive(verdict, long_comment)

        url = build_issue_url(report, config)
        assert len(url) <= MAX_URL_LENGTH
        # The full report should have been written out for attaching.
        saved = list((Path(config.paths.data_dir) / "reports").glob("*.json"))
        assert saved, "an oversized report should be saved locally"

    def test_submit_without_a_server_uses_github(self, verdict, config) -> None:
        config.privacy.server_url = ""
        report = build_false_positive(verdict, "No server configured here.")

        outcome = submit(report, config)
        assert outcome["method"] == "github"
        assert outcome["url"].startswith("https://github.com/")

    def test_submit_rejects_an_invalid_report(self, verdict, config) -> None:
        report = build_false_positive(verdict, "short")
        with pytest.raises(ValueError):
            submit(report, config)


# ----------------------------------------------------------------------
# sample upload consent
# ----------------------------------------------------------------------

class TestSampleConsent:
    def test_disabled_by_default(self, config, clean_file: Path) -> None:
        assert config.privacy.allow_sample_upload is False
        check = check_sample(clean_file, config)
        assert not check.allowed
        assert "disabled" in check.reason

    def test_allowed_when_enabled(self, config, tmp_path: Path) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / "binary.exe"
        path.write_bytes(b"MZ" + b"\x00" * 500)

        check = check_sample(path, config)
        assert check.allowed
        assert not check.needs_extra_confirmation

    @pytest.mark.parametrize("extension", sorted(NEVER_UPLOAD_EXTENSIONS)[:6])
    def test_credential_files_are_never_uploaded(
        self, config, tmp_path: Path, extension: str
    ) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / f"secret{extension}"
        path.write_bytes(b"-----BEGIN PRIVATE KEY-----")

        check = check_sample(path, config)
        assert not check.allowed
        assert "key, credential or password store" in check.reason

    @pytest.mark.parametrize(
        "name", ["id_rsa", "shadow", ".netrc", "credentials"]
    )
    def test_credential_names_are_never_uploaded(
        self, config, tmp_path: Path, name: str
    ) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / name
        path.write_bytes(b"secret material")
        assert not check_sample(path, config).allowed

    def test_documents_need_a_second_confirmation(
        self, config, tmp_path: Path
    ) -> None:
        """A user reporting a PDF rarely means to send us the PDF."""
        config.privacy.allow_sample_upload = True
        path = tmp_path / "tax-return.pdf"
        path.write_bytes(b"%PDF-1.7\n" + b"personal financial data " * 50)

        check = check_sample(path, config)
        assert check.allowed
        assert check.needs_extra_confirmation
        assert "personal information" in check.reason

    def test_oversized_files_are_refused(self, config, tmp_path: Path) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / "huge.bin"
        # Sparse write, so the test stays fast.
        with open(path, "wb") as handle:
            handle.seek(MAX_SAMPLE_SIZE + 1024)
            handle.write(b"\0")

        check = check_sample(path, config)
        assert not check.allowed
        assert "upload limit" in check.reason

    def test_empty_file_is_refused(self, config, tmp_path: Path) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / "empty.bin"
        path.touch()
        assert not check_sample(path, config).allowed

    def test_upload_refuses_without_second_confirmation(
        self, config, tmp_path: Path
    ) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / "notes.pdf"
        path.write_bytes(b"%PDF-1.7\ncontent")

        class ExplodingClient:
            def upload_sample(self, *args, **kwargs):
                raise AssertionError("must not upload without confirmation")

        result = upload_sample(ExplodingClient(), "report-1", path, config)
        assert result["uploaded"] is False
        assert result["needs_confirmation"] is True

    def test_upload_proceeds_with_confirmation(self, config, tmp_path: Path) -> None:
        config.privacy.allow_sample_upload = True
        path = tmp_path / "notes.pdf"
        path.write_bytes(b"%PDF-1.7\ncontent")
        sent: dict = {}

        class RecordingClient:
            def upload_sample(self, report_id, filename, content, content_type):
                sent.update(
                    report_id=report_id, filename=filename, size=len(content)
                )

                class Result:
                    accepted = True
                    message = "stored"

                return Result()

        result = upload_sample(
            RecordingClient(), "report-1", path, config,
            extra_confirmation_given=True,
        )
        assert result["uploaded"] is True
        assert sent["filename"] == "notes.pdf"


# ----------------------------------------------------------------------
# telemetry
# ----------------------------------------------------------------------

class TestTelemetry:
    def test_disabled_by_default(self, config) -> None:
        assert TelemetryCollector(config).enabled is False

    def test_needs_both_consent_and_a_server(self, config) -> None:
        config.privacy.telemetry = True
        assert TelemetryCollector(config).enabled is False  # no server

        config.privacy.server_url = "https://example.invalid"
        assert TelemetryCollector(config).enabled is True

    def test_flush_does_nothing_when_disabled(self, config, scanner, corpus) -> None:
        collector = TelemetryCollector(config)
        collector.record_scan(scanner.scan_paths([corpus]))
        assert collector.flush() is False

    def test_batch_contains_no_paths_or_hashes(
        self, config, scanner, corpus: Path
    ) -> None:
        collector = TelemetryCollector(config)
        result = scanner.scan_paths([corpus])
        collector.record_scan(result)

        payload = collector.preview()
        assert str(corpus) not in payload
        for verdict in result.verdicts:
            assert verdict.sha256 not in payload
            assert Path(verdict.path).name not in payload

    def test_batch_has_no_identifier(self, config, scanner, corpus: Path) -> None:
        collector = TelemetryCollector(config)
        collector.record_scan(scanner.scan_paths([corpus]))
        batch = json.loads(collector.preview())

        for key in batch:
            assert "id" not in key.lower() or key == "created_at"

    def test_counts_are_bucketed(self, config, scanner, corpus: Path) -> None:
        collector = TelemetryCollector(config)
        collector.record_scan(scanner.scan_paths([corpus]))
        batch = json.loads(collector.preview())
        # A bucket label, never the exact count.
        assert "-" in batch["files_scanned_bucket"] or batch["files_scanned_bucket"] in {
            "0", "1000000+",
        }

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(0, "0"), (1, "1-9"), (5, "1-9"), (10, "10-99"), (150, "100-999"),
         (5_000_000, "1000000+")],
    )
    def test_bucket_boundaries(self, value: int, expected: str) -> None:
        assert bucket(value) == expected

    def test_reset_clears_counters(self, config, scanner, corpus: Path) -> None:
        collector = TelemetryCollector(config)
        collector.record_scan(scanner.scan_paths([corpus]))
        assert collector.build_batch().scan_count == 1

        collector.reset()
        assert collector.build_batch().is_empty


# ----------------------------------------------------------------------
# client
# ----------------------------------------------------------------------

class TestServerClient:
    def test_unconfigured_client_refuses_to_send(self, config) -> None:
        from sentinel.feedback.client import ServerClient, ServerError

        client = ServerClient(config.privacy)
        assert not client.configured
        with pytest.raises(ServerError, match="no server configured"):
            client.lookup_hashes(["a" * 64])

    def test_empty_lookup_short_circuits(self, config) -> None:
        from sentinel.feedback.client import ServerClient

        config.privacy.server_url = "https://example.invalid"
        assert ServerClient(config.privacy).lookup_hashes([]) == {}
