from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.attack_scenarios import SCENARIOS, SCENARIOS_BY_ID
from app.database import get_db
from app.models import Session as SessionModel
from app.models import User
from app.schemas import AttackScenarioOut, RunScenarioRequest
from app.security.gateway import process_chat_message
from app.seed_data import FINASSIST_AGENT_ID

router = APIRouter(prefix="/api", tags=["attack-simulator"])


@router.get("/attack-scenarios", response_model=list[AttackScenarioOut])
def list_scenarios():
    return [
        AttackScenarioOut(
            scenario_id=s.scenario_id,
            name=s.name,
            category=s.category,
            description=s.description,
            expected_outcome=s.expected_outcome,
            prompts=s.prompts,
        )
        for s in SCENARIOS
    ]


def _default_user(db: DBSession) -> User:
    user = db.query(User).filter(User.role == "customer").first()
    if not user:
        raise HTTPException(status_code=500, detail="No seeded customer user found; has the database been seeded?")
    return user


@router.post("/attack-scenarios/run")
def run_scenario(req: RunScenarioRequest, db: DBSession = Depends(get_db)):
    scenario = SCENARIOS_BY_ID.get(req.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Unknown scenario_id: {req.scenario_id}")

    user = db.query(User).filter(User.user_id == req.user_id).first() if req.user_id else _default_user(db)
    if not user:
        raise HTTPException(status_code=404, detail=f"Unknown user_id: {req.user_id}")

    session = SessionModel(user_id=user.user_id, agent_id=FINASSIST_AGENT_ID, label=f"attack:{scenario.scenario_id}")
    db.add(session)
    db.commit()
    db.refresh(session)

    turns = []
    for prompt in scenario.prompts:
        result = process_chat_message(db, session=session, user=user, message=prompt, event_type="attack_simulation")
        decision = result["decision"]
        turns.append({
            "prompt": prompt,
            "event_id": result["event"].event_id,
            "tool_name": result["tool_name"],
            "reply": result["reply"],
            "risk_score": decision.risk_score,
            "risk_level": decision.risk_level,
            "action": decision.action,
            "blocked": decision.blocked,
            "detection_types": decision.detection_types,
            "reasoning_summary": decision.reasoning_summary,
            "injection_classification": result["injection"].classification,
            "injection_score": result["injection"].injection_score,
        })

    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "expected_outcome": scenario.expected_outcome,
        "session_id": session.session_id,
        "turns": turns,
        "any_blocked": any(t["blocked"] for t in turns),
        "any_approval_required": any(t["action"] == "APPROVAL_REQUIRED" for t in turns),
    }


@router.post("/attack-scenarios/run-all")
def run_all_scenarios(db: DBSession = Depends(get_db)):
    results = []
    for scenario in SCENARIOS:
        results.append(run_scenario(RunScenarioRequest(scenario_id=scenario.scenario_id), db))
    return {"results": results}
