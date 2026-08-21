"""
Incidents FastAPI router — /incidents/* endpoints.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from auth.middleware import require_auth, require_analyst
from auth.models import User, UserRole
from webhooks.models import WebhookEventType
from webhooks.service import WebhookService

from .models import (
    Incident,
    IncidentCommentCreate,
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from .service import IncidentService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("", response_model=Incident, status_code=201)
async def create_incident(
    data: IncidentCreate,
    current_user: User = Depends(require_auth),
):
    incident = IncidentService.create(data, reporter_id=current_user.id)
    # Fire webhook
    await WebhookService.fire(
        WebhookEventType.INCIDENT_CREATED,
        incident.model_dump(),
    )
    return incident


@router.get("", response_model=list[Incident])
async def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    mine: bool = False,
    current_user: User = Depends(require_auth),
):
    reporter = current_user.id if mine else None
    # Analysts/admins see all; regular users only see their own
    if current_user.role == UserRole.USER:
        reporter = current_user.id
    return IncidentService.list_all(status=status, severity=severity, reporter_id=reporter)


@router.get("/stats")
async def incident_stats(_: User = Depends(require_analyst)):
    return IncidentService.stats()


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str, current_user: User = Depends(require_auth)):
    inc = IncidentService.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if current_user.role == UserRole.USER and inc.reporter_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return inc


@router.patch("/{incident_id}", response_model=Incident)
async def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    current_user: User = Depends(require_analyst),
):
    inc = IncidentService.update(incident_id, update)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    await WebhookService.fire(WebhookEventType.INCIDENT_UPDATED, inc.model_dump())
    if update.false_positive:
        await WebhookService.fire(WebhookEventType.FALSE_POSITIVE_FLAGGED, inc.model_dump())
    return inc


@router.post("/{incident_id}/comments", response_model=Incident)
async def add_comment(
    incident_id: str,
    body: IncidentCommentCreate,
    current_user: User = Depends(require_auth),
):
    inc = IncidentService.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if current_user.role == UserRole.USER and inc.reporter_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    inc = IncidentService.add_comment(
        incident_id, body,
        author_id=current_user.id,
        author_name=current_user.full_name,
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(incident_id: str, _: User = Depends(require_analyst)):
    if not IncidentService.delete(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
