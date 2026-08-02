"""Aggregate statistics and hash reputation lookup.

The lookup endpoint lives here rather than in its own router because it is
the read side of the same reputation data the stats summarise, and it is the
only endpoint the scanner calls during a scan.

It is a POST despite being a read: the request carries up to 256 digests,
which does not fit sensibly in a query string, and keeping hashes out of URLs
keeps them out of access logs and proxy caches.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.models import (
    HashLookupIn,
    HashLookupOut,
    HashRecord,
    HashResult,
    Report,
    ReportKind,
    ReportStatus,
    StatsOut,
    TelemetryBatch,
    Verdict,
)
from server.storage import get_session, rate_limit, require_token

log = logging.getLogger("sentinel.server.stats")

router = APIRouter()


@router.post(
    "/hashes/lookup",
    response_model=HashLookupOut,
    summary="Look up the reputation of a batch of file hashes",
)
async def lookup_hashes(
    payload: HashLookupIn,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
    _limit: Annotated[str, Depends(rate_limit)],
) -> HashLookupOut:
    """Return what is known about each digest.

    Digests with no record are omitted rather than returned as "unknown", so
    the response stays small when a client asks about a directory of
    ordinary files. Clean records *are* returned, because "we have seen this
    and it is fine" is useful information the client caches.
    """
    digests = payload.hashes
    records = session.scalars(
        select(HashRecord).where(HashRecord.sha256.in_(digests))
    ).all()

    results = {
        record.sha256: HashResult(
            verdict=record.verdict,
            name=record.name,
            severity=record.severity,
            detection_count=record.detection_count,
            engine_count=record.engine_count,
            first_seen=record.first_seen,
        )
        for record in records
        # Never volunteer an UNKNOWN record; it carries no information and
        # the client treats absence identically.
        if record.verdict is not Verdict.UNKNOWN
    }

    log.debug("hash lookup: %d queried, %d known", len(digests), len(results))
    return HashLookupOut(results=results, queried=len(digests))


@router.get(
    "/stats",
    response_model=StatsOut,
    summary="Aggregate statistics about reports and telemetry",
)
async def get_stats(
    session: Annotated[Session, Depends(get_session)],
) -> StatsOut:
    """Public summary. Deliberately requires no authentication.

    Nothing here identifies a submitter or a machine — it is counts of
    reports and detector names.
    """
    total = session.scalar(select(func.count()).select_from(Report)) or 0

    by_kind = {
        kind.value: (
            session.scalar(
                select(func.count()).select_from(Report).where(Report.kind == kind)
            )
            or 0
        )
        for kind in ReportKind
    }

    by_status = {
        state.value: (
            session.scalar(
                select(func.count()).select_from(Report).where(Report.status == state)
            )
            or 0
        )
        for state in ReportStatus
    }

    open_false_positives = (
        session.scalar(
            select(func.count())
            .select_from(Report)
            .where(
                Report.kind == ReportKind.FALSE_POSITIVE,
                Report.status.in_([ReportStatus.NEW, ReportStatus.TRIAGED]),
            )
        )
        or 0
    )

    hashes_known = session.scalar(select(func.count()).select_from(HashRecord)) or 0
    telemetry_count = (
        session.scalar(select(func.count()).select_from(TelemetryBatch)) or 0
    )

    return StatsOut(
        reports_total=total,
        reports_by_kind=by_kind,
        reports_by_status=by_status,
        open_false_positives=open_false_positives,
        hashes_known=hashes_known,
        telemetry_batches=telemetry_count,
        top_detectors=_top_detectors(session),
        top_threats=_top_threats(session),
    )


def _top_detectors(session: Session, limit: int = 10) -> dict[str, int]:
    """Which detectors appear most often in false-positive reports.

    This is the number a maintainer should watch: a detector at the top of
    this list is producing the most user-visible mistakes.
    """
    counter: Counter[str] = Counter()
    reports = session.scalars(
        select(Report).where(Report.kind == ReportKind.FALSE_POSITIVE).limit(2000)
    ).all()

    for report in reports:
        for detection in report.detections or []:
            name = str(detection.get("detector", "")).split(":")[0]
            if name:
                counter[name] += 1

    return dict(counter.most_common(limit))


def _top_threats(session: Session, limit: int = 10) -> dict[str, int]:
    """Most frequently reported threat names, from telemetry batches."""
    counter: Counter[str] = Counter()
    batches = session.scalars(
        select(TelemetryBatch)
        .order_by(TelemetryBatch.received_at.desc())
        .limit(1000)
    ).all()

    for batch in batches:
        for name, count in (batch.top_threats or {}).items():
            counter[name] += int(count)

    return dict(counter.most_common(limit))


@router.get(
    "/stats/detectors",
    summary="False-positive counts per detector",
)
async def detector_stats(
    session: Annotated[Session, Depends(get_session)],
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, object]:
    """Detail behind ``top_detectors``, for tuning work."""
    counts = _top_detectors(session, limit)
    total = sum(counts.values())
    return {
        "false_positives_by_detector": counts,
        "total": total,
        "note": (
            "A detector high in this list is producing the most user-visible "
            "mistakes. Consider lowering its confidence values before adding "
            "new rules to it."
        ),
    }
