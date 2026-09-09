import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session as DBSession

from app.database import SessionLocal, get_db
from app.models import Event
from app.schemas import EventOut

router = APIRouter(prefix="/api", tags=["events"])


@router.get("/events", response_model=list[EventOut])
def list_events(
    db: DBSession = Depends(get_db),
    limit: int = Query(50, le=500),
    offset: int = 0,
    session_id: str | None = None,
    risk_level: str | None = None,
    action: str | None = None,
    blocked: bool | None = None,
):
    q = db.query(Event)
    if session_id:
        q = q.filter(Event.session_id == session_id)
    if risk_level:
        q = q.filter(Event.risk_level == risk_level.upper())
    if action:
        q = q.filter(Event.action == action.upper())
    if blocked is not None:
        q = q.filter(Event.blocked == blocked)
    q = q.order_by(desc(Event.timestamp)).offset(offset).limit(limit)
    return q.all()


@router.get("/events/stream")
async def stream_events(request: Request):
    """
    Server-Sent Events stream of newly logged events, for the live
    Events page. Polls the database (no message broker needed for a
    single-process local demo) and pushes only genuinely new rows.

    NOTE: this route MUST be declared before /events/{event_id} --
    route matching is first-match-wins, and "stream" would otherwise be
    captured as an event_id path parameter.
    """

    async def event_generator():
        db = SessionLocal()
        try:
            last_seen = db.query(Event).order_by(desc(Event.timestamp)).first()
            last_timestamp = last_seen.timestamp if last_seen else None
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                query = db.query(Event).order_by(Event.timestamp.asc())
                if last_timestamp is not None:
                    query = query.filter(Event.timestamp > last_timestamp)
                new_events = query.all()
                for e in new_events:
                    payload = EventOut.model_validate(e).model_dump(mode="json")
                    yield f"data: {json.dumps(payload)}\n\n"
                    last_timestamp = e.timestamp
                await asyncio.sleep(1.0)
        finally:
            db.close()

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: str, db: DBSession = Depends(get_db)):
    return db.query(Event).filter(Event.event_id == event_id).first()


@router.get("/sessions/{session_id}/events", response_model=list[EventOut])
def get_session_events(session_id: str, db: DBSession = Depends(get_db)):
    return (
        db.query(Event)
        .filter(Event.session_id == session_id)
        .order_by(Event.timestamp.asc())
        .all()
    )


@router.get("/sessions")
def list_sessions(db: DBSession = Depends(get_db), limit: int = Query(50, le=200)):
    """Distinct sessions that have at least one event, most recent first --
    used by the Session Replay page's session picker."""
    # SQLite has no DISTINCT ON; dedupe in Python instead, keeping each
    # session's most recent event timestamp for ordering.
    latest_by_session: dict[str, dict] = {}
    for e in db.query(Event).order_by(desc(Event.timestamp)).limit(2000).all():
        if e.session_id not in latest_by_session:
            latest_by_session[e.session_id] = {
                "session_id": e.session_id,
                "user_id": e.user_id,
                "last_event_at": e.timestamp,
                "label": None,
            }
    sessions = sorted(latest_by_session.values(), key=lambda s: s["last_event_at"], reverse=True)[:limit]
    return sessions
