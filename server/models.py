"""Database models and API schemas for the reporting server.

Two layers, deliberately separate:

* SQLAlchemy ORM models — what is stored.
* Pydantic schemas — what crosses the wire.

Keeping them apart means a stored column can never leak into a response by
accident. Notably, :class:`Report` holds a ``submitter_ip_hash`` used only
for rate limiting; no schema exposes it.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Base(DeclarativeBase):
    pass


# ----------------------------------------------------------------------
# enums
# ----------------------------------------------------------------------

class ReportKind(str, enum.Enum):
    FALSE_POSITIVE = "false_positive"
    MISSED_DETECTION = "missed_detection"
    BUG = "bug"


class ReportStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    FIXED = "fixed"
    DUPLICATE = "duplicate"


class Verdict(str, enum.Enum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ----------------------------------------------------------------------
# ORM models
# ----------------------------------------------------------------------

class Report(Base):
    """A detection-quality report submitted by a client."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[ReportKind] = mapped_column(Enum(ReportKind), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus), default=ReportStatus.NEW, nullable=False
    )

    file_name: Mapped[str] = mapped_column(String(512), default="")
    file_extension: Mapped[str] = mapped_column(String(32), default="")
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    file_type: Mapped[str] = mapped_column(String(32), default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    md5: Mapped[str] = mapped_column(String(32), default="")
    sha1: Mapped[str] = mapped_column(String(40), default="")

    comment: Mapped[str] = mapped_column(Text, default="")
    origin: Mapped[str] = mapped_column(String(512), default="")
    detections: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    environment: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)

    #: Triage output.
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    triage_notes: Mapped[list[str]] = mapped_column(JSON, default=list)

    has_sample: Mapped[bool] = mapped_column(Boolean, default=False)
    sample_consented: Mapped[bool] = mapped_column(Boolean, default=False)

    #: Salted hash of the submitter's IP, for rate limiting only. Never
    #: returned by any endpoint.
    submitter_ip_hash: Mapped[str] = mapped_column(String(64), default="", index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    samples: Mapped[list[Sample]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_reports_kind_status", "kind", "status"),
        Index("idx_reports_priority_created", "priority", "created_at"),
    )


class Sample(Base):
    """An uploaded file attached to a report."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    size: Mapped[int] = mapped_column(Integer, default=0)
    original_name: Mapped[str] = mapped_column(String(512), default="")
    content_type: Mapped[str] = mapped_column(String(128), default="")
    #: Path relative to the sample directory. Samples are stored obfuscated.
    stored_path: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    report: Mapped[Report] = relationship(back_populates="samples")


class HashRecord(Base):
    """Reputation data served by the hash lookup endpoint."""

    __tablename__ = "hashes"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict), default=Verdict.UNKNOWN, index=True
    )
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    engine_count: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(128), default="")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class TelemetryBatch(Base):
    """One anonymous counters submission.

    There is deliberately no client identifier column. Batches cannot be
    linked to each other or to a machine — see the client-side module
    ``sentinel.feedback.telemetry`` for the full statement.
    """

    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_version: Mapped[str] = mapped_column(String(32), default="", index=True)
    signature_version: Mapped[str] = mapped_column(String(32), default="")
    os_family: Mapped[str] = mapped_column(String(32), default="", index=True)
    python_version: Mapped[str] = mapped_column(String(32), default="")
    detections_by_detector: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    verdicts_by_severity: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    top_threats: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    files_scanned_bucket: Mapped[str] = mapped_column(String(32), default="0")
    errors_bucket: Mapped[str] = mapped_column(String(32), default="0")
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


# ----------------------------------------------------------------------
# API schemas
# ----------------------------------------------------------------------

HEX64 = r"^[0-9a-fA-F]{64}$"


class FileFactsIn(BaseModel):
    """The file description a client submits."""

    name: str = Field(default="", max_length=512)
    extension: str = Field(default="", max_length=32)
    size: int = Field(default=0, ge=0)
    sha256: str = Field(..., pattern=HEX64)
    md5: str = Field(default="", max_length=32)
    sha1: str = Field(default="", max_length=40)
    file_type: str = Field(default="", max_length=32)


class ReportIn(BaseModel):
    """Body of ``POST /v1/reports``."""

    kind: ReportKind
    file: FileFactsIn
    comment: str = Field(default="", max_length=8000)
    detections: list[dict[str, Any]] = Field(default_factory=list)
    origin: str = Field(default="", max_length=512)
    sample_consented: bool = False
    environment: dict[str, str] = Field(default_factory=dict)
    created_at: float = 0.0
    format_version: int = 1

    @field_validator("detections")
    @classmethod
    def _cap_detections(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # A malformed or hostile client could otherwise ship megabytes of
        # JSON into a column we index on.
        return value[:50]

    @field_validator("comment")
    @classmethod
    def _require_comment(cls, value: str) -> str:
        if len(value.strip()) < 10:
            raise ValueError(
                "please explain what you expected — a report without an "
                "explanation cannot be acted on"
            )
        return value.strip()


class ReportOut(BaseModel):
    """Response for a submitted report."""

    accepted: bool = True
    report_id: str
    message: str = ""
    url: str = ""
    priority: int = 0


class ReportDetail(BaseModel):
    """Full report, for the maintainer-facing listing."""

    id: str
    kind: ReportKind
    status: ReportStatus
    file_name: str
    file_size: int
    file_type: str
    sha256: str
    comment: str
    origin: str
    detections: list[dict[str, Any]]
    environment: dict[str, str]
    priority: int
    triage_notes: list[str]
    has_sample: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class HashLookupIn(BaseModel):
    """Body of ``POST /v1/hashes/lookup``."""

    hashes: list[str] = Field(..., min_length=1, max_length=256)

    @field_validator("hashes")
    @classmethod
    def _validate(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            digest = item.strip().lower()
            if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
                raise ValueError(f"{item!r} is not a sha256 hex digest")
            cleaned.append(digest)
        return cleaned


class HashResult(BaseModel):
    """One reputation record."""

    verdict: Verdict
    name: str = ""
    severity: Severity = Severity.MEDIUM
    detection_count: int = 0
    engine_count: int = 0
    first_seen: datetime | None = None

    model_config = {"from_attributes": True}


class HashLookupOut(BaseModel):
    """Response of a hash lookup. Unknown digests are simply absent."""

    results: dict[str, HashResult] = Field(default_factory=dict)
    queried: int = 0


class TelemetryIn(BaseModel):
    """Body of ``POST /v1/telemetry``."""

    app_version: str = Field(default="", max_length=32)
    signature_version: str = Field(default="", max_length=32)
    os_family: str = Field(default="", max_length=32)
    python_version: str = Field(default="", max_length=32)
    detections_by_detector: dict[str, int] = Field(default_factory=dict)
    verdicts_by_severity: dict[str, int] = Field(default_factory=dict)
    top_threats: dict[str, int] = Field(default_factory=dict)
    files_scanned_bucket: str = Field(default="0", max_length=32)
    errors_bucket: str = Field(default="0", max_length=32)
    scan_count: int = Field(default=0, ge=0)
    created_at: int = 0

    @field_validator("detections_by_detector", "verdicts_by_severity", "top_threats")
    @classmethod
    def _cap(cls, value: dict[str, int]) -> dict[str, int]:
        return dict(list(value.items())[:100])


class StatsOut(BaseModel):
    """Aggregate statistics published by the server."""

    reports_total: int = 0
    reports_by_kind: dict[str, int] = Field(default_factory=dict)
    reports_by_status: dict[str, int] = Field(default_factory=dict)
    open_false_positives: int = 0
    hashes_known: int = 0
    telemetry_batches: int = 0
    top_detectors: dict[str, int] = Field(default_factory=dict)
    top_threats: dict[str, int] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=utcnow)


class HealthOut(BaseModel):
    status: str = "ok"
    version: str = ""
    database: str = "ok"
