from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine, SessionLocal
from app import seed_data
from app.api import chat, events, alerts, dashboard, policies, attack_simulator, model_performance


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
