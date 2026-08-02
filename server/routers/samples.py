"""Sample upload and retrieval.

Samples are live malware. Three rules govern this router:

1. A sample is only accepted for a report whose submitter set
   ``sample_consented``. Consent is recorded at report time and cannot be
   granted retroactively by the upload call itself.
2. Downloads never return the raw bytes with a guessable content type. The
   response is ``application/octet-stream`` with a filename that does not
   preserve the original extension, so a browser cannot be tricked into
   executing it.
3. Everything is size-capped before it reaches memory.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from server.models import Report, Sample
from server.storage import (
    MAX_UPLOAD,
    get_session,
    load_sample,
    rate_limit,
    require_token,
    sample_exists,
    store_sample,
)

log = logging.getLogger("sentinel.server.samples")

router = APIRouter()

#: Read in chunks so a huge upload cannot be buffered whole before the size
#: check runs.
_CHUNK = 1024 * 1024


@router.post(
    "/reports/{report_id}/sample",
    status_code=status.HTTP_201_CREATED,
    summary="Attach a file to an existing report",
)
async def upload_sample(
    report_id: str,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
    _limit: Annotated[str, Depends(rate_limit)],
    file: UploadFile = File(...),
) -> dict[str, object]:
    """Store an uploaded sample against a report."""
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="no such report")

    if not report.sample_consented:
        # The consent flag is set when the report is created. Refusing here
        # means a stolen report id cannot be used to push samples.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "this report was submitted without consent to attach a sample; "
                "submit a new report with sample_consented set"
            ),
        )

    if report.has_sample:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a sample is already attached to this report",
        )

    content = bytearray()
    while chunk := await file.read(_CHUNK):
        content.extend(chunk)
        if len(content) > MAX_UPLOAD:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"sample exceeds the {MAX_UPLOAD} byte limit",
            )

    if not content:
        raise HTTPException(status_code=400, detail="the uploaded file was empty")

    payload = bytes(content)
    digest = hashlib.sha256(payload).hexdigest()

    # The uploaded bytes must be the file the report describes. Without this
    # check a report about a benign file could be used to store anything.
    if digest != report.sha256:
        raise HTTPException(
            status_code=400,
            detail=(
                f"uploaded content hashes to {digest[:16]}… but the report "
                f"describes {report.sha256[:16]}…"
            ),
        )

    if sample_exists(digest):
        log.info("sample %s already stored; linking report %s", digest[:12], report_id)

    try:
        stored_path, size = store_sample(payload, digest)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except OSError as exc:
        log.error("cannot store sample: %s", exc)
        raise HTTPException(status_code=500, detail="could not store the sample") from exc

    sample = Sample(
        report_id=report.id,
        sha256=digest,
        size=size,
        original_name=(file.filename or "")[:512],
        content_type=(file.content_type or "application/octet-stream")[:128],
        stored_path=stored_path,
    )
    session.add(sample)
    report.has_sample = True
    session.commit()

    log.warning(
        "stored sample %s (%d bytes) for report %s", digest[:12], size, report_id
    )
    return {"accepted": True, "sha256": digest, "size": size, "message": "sample stored"}


@router.get(
    "/samples/{sha256}",
    summary="Download a stored sample (maintainers only)",
    response_class=Response,
)
async def download_sample(
    sha256: str,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
) -> Response:
    """Return a stored sample.

    The response is deliberately awkward to execute: a generic content type
    and a ``.sample`` filename, sent as an attachment. Anyone analysing it
    will rename it deliberately; nobody will run it by double-clicking.
    """
    digest = sha256.strip().lower()
    if len(digest) != 64:
        raise HTTPException(status_code=400, detail="not a sha256 digest")

    record = session.scalar(select(Sample).where(Sample.sha256 == digest))
    if record is None:
        raise HTTPException(status_code=404, detail="no such sample")

    try:
        content = load_sample(record.stored_path)
    except (FileNotFoundError, ValueError) as exc:
        log.error("sample %s is recorded but unreadable: %s", digest[:12], exc)
        raise HTTPException(status_code=404, detail="the sample is not on disk") from exc

    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{digest}.sample"',
            "X-Content-Type-Options": "nosniff",
            "X-Sentinel-Warning": "This file may be live malware. Handle in isolation.",
        },
    )


@router.get(
    "/samples/{sha256}/info",
    summary="Metadata about a stored sample, without downloading it",
)
async def sample_info(
    sha256: str,
    session: Annotated[Session, Depends(get_session)],
    _token: Annotated[str, Depends(require_token)],
) -> dict[str, object]:
    digest = sha256.strip().lower()
    record = session.scalar(select(Sample).where(Sample.sha256 == digest))
    if record is None:
        raise HTTPException(status_code=404, detail="no such sample")

    return {
        "sha256": record.sha256,
        "size": record.size,
        "original_name": record.original_name,
        "content_type": record.content_type,
        "report_id": record.report_id,
        "created_at": record.created_at.isoformat(),
    }
