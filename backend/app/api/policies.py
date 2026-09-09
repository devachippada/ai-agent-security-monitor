import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import Policy
from app.schemas import PolicyOut, PolicyUpdate

router = APIRouter(prefix="/api", tags=["policies"])


@router.get("/policies", response_model=list[PolicyOut])
def list_policies(db: DBSession = Depends(get_db)):
    return db.query(Policy).order_by(Policy.tool_name).all()


@router.patch("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(policy_id: str, update: PolicyUpdate, db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.policy_id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if update.requires_approval is not None:
        policy.requires_approval = update.requires_approval
    if update.max_calls_per_session is not None:
        policy.max_calls_per_session = update.max_calls_per_session
    if update.block_threshold is not None:
        policy.block_threshold = update.block_threshold
    if update.enabled is not None:
        policy.enabled = update.enabled
    if update.allowed_roles is not None:
        policy.allowed_roles = json.dumps(update.allowed_roles)

    db.commit()
    db.refresh(policy)
    return policy
