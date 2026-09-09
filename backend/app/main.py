from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import seed_data
from app.api import (
    alerts,
    attack_simulator,
    chat,
    dashboard,
    events,
    model_performance,
    policies,
)
from app.database import Base, SessionLocal, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_data.seed(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="AI Agent Security Monitor",
    description=(
        "A security gateway, detection pipeline, and monitoring dashboard for the "
        "simulated FinAssist customer-support/finance agent. All data is synthetic "
        "and every 'external action' (email, refund, export) is simulated."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(chat.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(policies.router)
app.include_router(attack_simulator.router)
app.include_router(model_performance.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Optional single-container deployment mode: if a built frontend has been
# placed at backend/static (the Docker image does this at build time), serve
# it from this same FastAPI process so the whole app is one deployable
# service with no CORS/base-URL configuration needed -- the frontend already
# talks to a same-origin "/api" (see frontend/src/api/client.ts).
#
# This block is registered LAST and deliberately: Starlette matches routes
# in declaration order, so every /api/* route above (and FastAPI's own
# /docs, /redoc, /openapi.json) must be registered first or this catch-all
# would swallow them -- the exact bug class fixed earlier in app/api/events.py
# for the SSE route, generalized here on purpose.
#
# In local dev (`uvicorn app.main:app --reload` without a Docker build) this
# directory simply doesn't exist, so none of this registers and the app
# behaves exactly as before -- the frontend is served by the separate Vite
# dev server instead.
# ---------------------------------------------------------------------------
_FRONTEND_DIST = Path(__file__).resolve().parent.parent / "static"

if _FRONTEND_DIST.is_dir():
    _assets_dir = _FRONTEND_DIST / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """SPA fallback: serve the matching built file if one exists (e.g.
        favicon.svg), otherwise index.html so client-side routing (React
        Router) can take over for any app route like /dashboard or /trace.

        A path under /api/ that didn't match a real route above is a bad
        or mistyped API call, not a frontend page -- it must 404 rather
        than silently returning the SPA's index.html with a 200, which
        would mask real client/API bugs behind a fake success response."""
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = _FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
