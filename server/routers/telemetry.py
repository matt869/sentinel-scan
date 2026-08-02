"""Anonymous telemetry ingestion.

The contract the client makes to its users constrains this endpoint:

* No client identifier is accepted or stored. There is no column for one.
* The submitter's IP is not recorded on the row — the rate limiter sees a
  salted hash and nothing is persisted.
* Batches are stored as-is and only ever queried in aggregate.

If you extend this, keep those properties. The client's privacy statement
(docs/privacy.md) is a promise about what this server can possibly know.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.models import TelemetryBatch, TelemetryIn
from server.storage import get_session, rate_limit

log = logging.getLogger("sentinel.server.telemetry")

router = APIRouter()


@router.post(
    "/telemetry",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit an anonymous counters batch",
)
async def submit_telemetry(
    payload: TelemetryIn,
    session: Annotated[Session, Depends(get_session)],
    _limit: Annotated[str, Depends(rate_limit)],
) -> dict[str, object]:
    """Accept a telemetry batch.

    Deliberately unauthenticated: requiring a token would mean issuing one
    per install, which is exactly the persistent identifier the client
    promises not to have.
    """
    batch = TelemetryBatch(
        app_version=payload.app_version[:32],
        signature_version=payload.signature_version[:32],
        os_family=payload.os_family[:32],
        python_version=payload.python_version[:32],
        detections_by_detector=payload.detections_by_detector,
        verdicts_by_severity=payload.verdicts_by_severity,
        top_threats=payload.top_threats,
        files_scanned_bucket=payload.files_scanned_bucket[:32],
        errors_bucket=payload.errors_bucket[:32],
        scan_count=payload.scan_count,
    )
    session.add(batch)
    session.commit()

    log.debug(
        "telemetry batch accepted: %s on %s, %d scans",
        payload.app_version, payload.os_family, payload.scan_count,
    )
    return {"accepted": True}


@router.get(
    "/telemetry/summary",
    summary="Aggregated telemetry over a time window",
)
async def telemetry_summary(
    session: Annotated[Session, Depends(get_session)],
    days: int = Query(default=30, ge=1, le=365),
) -> dict[str, object]:
    """Roll up recent batches.

    Only aggregates are exposed. Individual batches are never returned, so
    a single unusual submission cannot be singled out.
    """
    since = datetime.now(tz=timezone.utc) - timedelta(days=days)

    batches = session.scalars(
        select(TelemetryBatch).where(TelemetryBatch.received_at >= since)
    ).all()

    if not batches:
        return {
            "window_days": days,
            "batches": 0,
            "note": "no telemetry received in this window",
        }

    by_version: dict[str, int] = {}
    by_os: dict[str, int] = {}
    detectors: dict[str, int] = {}
    severities: dict[str, int] = {}
    threats: dict[str, int] = {}
    total_scans = 0

    for batch in batches:
        by_version[batch.app_version] = by_version.get(batch.app_version, 0) + 1
        by_os[batch.os_family] = by_os.get(batch.os_family, 0) + 1
        total_scans += batch.scan_count

        for name, count in (batch.detections_by_detector or {}).items():
            detectors[name] = detectors.get(name, 0) + int(count)
        for name, count in (batch.verdicts_by_severity or {}).items():
            severities[name] = severities.get(name, 0) + int(count)
        for name, count in (batch.top_threats or {}).items():
            threats[name] = threats.get(name, 0) + int(count)

    return {
        "window_days": days,
        "batches": len(batches),
        "total_scans": total_scans,
        "by_app_version": dict(sorted(by_version.items(), key=lambda i: -i[1])),
        "by_os": dict(sorted(by_os.items(), key=lambda i: -i[1])),
        "detections_by_detector": dict(
            sorted(detectors.items(), key=lambda i: -i[1])[:20]
        ),
        "verdicts_by_severity": severities,
        "top_threats": dict(sorted(threats.items(), key=lambda i: -i[1])[:20]),
    }


@router.delete(
    "/telemetry",
    summary="Delete telemetry older than a retention window",
)
async def prune_telemetry(
    session: Annotated[Session, Depends(get_session)],
    older_than_days: int = Query(default=180, ge=1),
) -> dict[str, int]:
    """Enforce retention.

    Telemetry is only useful in aggregate and only recently; keeping it
    forever is a liability with no benefit. Run this from cron.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=older_than_days)

    count = (
        session.scalar(
            select(func.count())
            .select_from(TelemetryBatch)
            .where(TelemetryBatch.received_at < cutoff)
        )
        or 0
    )

    if count:
        for batch in session.scalars(
            select(TelemetryBatch).where(TelemetryBatch.received_at < cutoff)
        ).all():
            session.delete(batch)
        session.commit()
        log.info("pruned %d telemetry batches older than %d days", count, older_than_days)

    return {"deleted": count}
