"""Report submission and listing."""

from __future__ import annotations

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.models import (
    Report,
    ReportDetail,
    ReportIn,
    ReportKind,
    ReportOut,
    ReportStatus,
)
from server.storage import get_session, rate_limit, require_token
from server.triage import priority_label, triage

log = logging.getLogger("sentinel.server.reports")

router = APIRouter()


@router.post(
    "/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a false-positive or missed-detection report",
)
async def create_report(
    payload: ReportIn,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
    submitter: Annotated[str, Depends(rate_limit)],
) -> ReportOut:
    """Accept a report, triage it, and return its id.

    Duplicate detection is by sha256 plus kind: the same file reported as a
    false positive twice is a duplicate, but the same file reported as a
    missed detection is a different claim.
    """
    digest = payload.file.sha256.lower()

    duplicates = session.scalar(
        select(func.count())
        .select_from(Report)
        .where(Report.sha256 == digest, Report.kind == payload.kind)
    ) or 0

    report = Report(
        id=secrets.token_hex(16),
        kind=payload.kind,
        status=ReportStatus.NEW,
        file_name=payload.file.name[:512],
        file_extension=payload.file.extension[:32],
        file_size=payload.file.size,
        file_type=payload.file.file_type[:32],
        sha256=digest,
        md5=payload.file.md5.lower()[:32],
        sha1=payload.file.sha1.lower()[:40],
        comment=payload.comment,
        origin=payload.origin[:512],
        detections=payload.detections,
        environment=payload.environment,
        sample_consented=payload.sample_consented,
        has_sample=False,
        submitter_ip_hash=submitter,
    )

    result = triage(report, duplicate_count=duplicates)
    report.priority = result.priority
    report.triage_notes = result.notes
    if result.suggested_status:
        report.status = ReportStatus(result.suggested_status)

    session.add(report)
    session.commit()

    log.info(
        "report %s accepted: %s %s priority=%d (%s) duplicates=%d",
        report.id, report.kind.value, digest[:12], report.priority,
        priority_label(report.priority), duplicates,
    )

    message = (
        f"Thank you. Triaged as {priority_label(report.priority)} priority."
    )
    if duplicates:
        message += f" {duplicates} earlier report(s) exist for this file."
    if payload.sample_consented:
        message += " You may now attach the sample."

    return ReportOut(
        accepted=True,
        report_id=report.id,
        message=message,
        priority=report.priority,
    )


@router.get(
    "/reports",
    response_model=list[ReportDetail],
    summary="List reports, newest and highest priority first",
)
async def list_reports(
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
    kind: ReportKind | None = None,
    report_status: ReportStatus | None = Query(default=None, alias="status"),
    min_priority: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[Report]:
    """Maintainer-facing listing, filterable by kind, status and priority."""
    query = select(Report).where(Report.priority >= min_priority)
    if kind is not None:
        query = query.where(Report.kind == kind)
    if report_status is not None:
        query = query.where(Report.status == report_status)

    query = (
        query.order_by(Report.priority.desc(), Report.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(session.scalars(query).all())


@router.get(
    "/reports/{report_id}",
    response_model=ReportDetail,
    summary="Fetch one report",
)
async def get_report(
    report_id: str,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="no such report")
    return report


@router.patch(
    "/reports/{report_id}/status",
    response_model=ReportDetail,
    summary="Update a report's triage status",
)
async def update_status(
    report_id: str,
    new_status: ReportStatus,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="no such report")

    report.status = new_status
    session.commit()
    log.info("report %s status -> %s", report_id, new_status.value)
    return report


@router.get(
    "/reports/by-hash/{sha256}",
    response_model=list[ReportDetail],
    summary="All reports for one file",
)
async def reports_by_hash(
    sha256: str,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
) -> list[Report]:
    """Used to check whether a file has already been reported."""
    digest = sha256.strip().lower()
    if len(digest) != 64:
        raise HTTPException(status_code=400, detail="not a sha256 digest")

    return list(
        session.scalars(
            select(Report)
            .where(Report.sha256 == digest)
            .order_by(Report.created_at.desc())
        ).all()
    )
