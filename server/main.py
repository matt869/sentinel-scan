"""FastAPI application for the Sentinel reporting server.

Run locally::

    pip install -r requirements-dev.txt
    uvicorn server.main:app --reload

Or with Docker::

    docker compose -f server/docker-compose.yml up

Authentication: write endpoints require a bearer token from
``SENTINEL_SERVER_TOKENS``. If that variable is empty the server runs open —
fine for local development, wrong for anything reachable. The startup log
says so loudly.

The auth and rate-limit dependencies live in :mod:`server.storage` so the
routers can import them without a circular import through this module.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from server.models import HealthOut
from server.routers import reports, samples, stats, telemetry
from server.storage import API_TOKENS, health_check, init_db, rate_limit, require_token

logging.basicConfig(
    level=os.environ.get("SENTINEL_SERVER_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("sentinel.server")

VERSION = "0.4.0"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create tables on startup and warn about an open configuration."""
    init_db()
    if not API_TOKENS:
        log.warning(
            "SENTINEL_SERVER_TOKENS is empty — write endpoints are "
            "UNAUTHENTICATED. Set it before exposing this server to a network."
        )
    else:
        log.info("authentication enabled (%d token(s) configured)", len(API_TOKENS))
    log.info("Sentinel reporting server %s ready", VERSION)
    yield
    log.info("shutting down")


app = FastAPI(
    title="Sentinel Scan reporting server",
    description=(
        "Collects detection-quality reports, serves hash reputation, and "
        "accepts anonymous telemetry. Every client-side feature that talks to "
        "this server is opt-in."
    ),
    version=VERSION,
    lifespan=lifespan,
)

# The API is consumed by a desktop client, not a browser, so CORS stays
# closed unless a dashboard origin is configured.
_origins = [
    o.strip()
    for o in os.environ.get("SENTINEL_SERVER_CORS_ORIGINS", "").split(",")
    if o.strip()
]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.get("/health", response_model=HealthOut, tags=["meta"])
async def health() -> HealthOut:
    """Liveness probe. Never requires authentication."""
    return HealthOut(status="ok", version=VERSION, database=health_check())


@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {
        "name": "Sentinel Scan reporting server",
        "version": VERSION,
        "docs": "/docs",
    }


app.include_router(reports.router, prefix="/v1", tags=["reports"])
app.include_router(samples.router, prefix="/v1", tags=["samples"])
app.include_router(stats.router, prefix="/v1", tags=["stats"])
app.include_router(telemetry.router, prefix="/v1", tags=["telemetry"])


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    """Turn a stray ValueError into a 400 rather than a 500."""
    log.warning("bad request to %s: %s", request.url.path, exc)
    return JSONResponse(status_code=400, content={"detail": str(exc)})


__all__ = ["app", "rate_limit", "require_token"]


def run() -> None:  # pragma: no cover - convenience entry point
    """Run with uvicorn, honouring the SENTINEL_SERVER_* variables."""
    import uvicorn

    uvicorn.run(
        "server.main:app",
        host=os.environ.get("SENTINEL_SERVER_HOST", "0.0.0.0"),
        port=int(os.environ.get("SENTINEL_SERVER_PORT", "8000")),
        reload=os.environ.get("SENTINEL_SERVER_RELOAD", "").lower() in {"1", "true"},
    )


if __name__ == "__main__":  # pragma: no cover
    run()
