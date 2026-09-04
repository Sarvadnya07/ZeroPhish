"""
Incidents FastAPI router — /incidents/* endpoints.

Provides endpoints for:
- Creating, listing, retrieving, updating, and deleting incidents
- Adding comments to incidents
- Incident statistics (analyst+ only)
- Role-based access control (users see only their own, analysts see all)
"""

from __future__ import annotations

import logging
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from auth.middleware import require_analyst, require_auth
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

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/incidents", tags=["incidents"])


# ---------- Endpoints ----------
@router.post(
    "",
    response_model=Incident,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new incident",
)
async def create_incident(
    data: IncidentCreate,
    current_user: Annotated[User, Depends(require_auth)],
) -> Incident:
    """Create a new incident ticket. Any authenticated user can report an incident."""
    try:
        incident = IncidentService.create(data, reporter_id=current_user.id)
        clean_inc_id = str(incident.id).replace("\n", "").replace("\r", "")
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        logger.info("Incident created: %s by user %s", clean_inc_id, clean_user_id)
        # Fire webhook asynchronously (fire-and-forget)
        await WebhookService.fire(WebhookEventType.INCIDENT_CREATED, incident.model_dump())
        return incident
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        logger.exception("Failed to create incident for user %s", clean_user_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Incident creation failed")


@router.get(
    "",
    response_model=List[Incident],
    summary="List incidents",
    description="Users see only their own reports; analysts/admins see all.",
)
async def list_incidents(
    current_user: Annotated[User, Depends(require_auth)],
    status_filter: Annotated[Optional[IncidentStatus], Query(description="Filter by status")] = None,
    severity: Annotated[Optional[IncidentSeverity], Query(description="Filter by severity")] = None,
    mine: Annotated[bool, Query(description="If true, return only incidents reported by the current user")] = False,
) -> List[Incident]:
    """List incidents with optional filters."""
    reporter_id = current_user.id if mine else None

    # Regular users can only see their own incidents
    if current_user.role == UserRole.USER:
        reporter_id = current_user.id

    try:
        return IncidentService.list_all(
            status=status_filter,
            severity=severity,
            reporter_id=reporter_id,
        )
    except Exception as e:
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        logger.exception("Failed to list incidents for user %s", clean_user_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch incidents")


@router.get(
    "/stats",
    response_model=dict,
    summary="Incident statistics",
    description="Analyst+ only.",
)
async def incident_stats(_: Annotated[User, Depends(require_analyst)]) -> dict:
    """Return summary statistics (counts by status, severity, etc.)."""
    try:
        return IncidentService.stats()
    except Exception as e:
        logger.exception("Failed to fetch incident stats")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch statistics")


@router.get(
    "/{incident_id}",
    response_model=Incident,
    summary="Get incident by ID",
)
async def get_incident(
    incident_id: Annotated[str, Path(min_length=1)],
    current_user: Annotated[User, Depends(require_auth)],
) -> Incident:
    """Retrieve a single incident. Users can only see their own."""
    inc = IncidentService.get(incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role == UserRole.USER and inc.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    return inc


@router.patch(
    "/{incident_id}",
    response_model=Incident,
    summary="Update an incident",
    description="Analyst+ only.",
)
async def update_incident(
    incident_id: Annotated[str, Path(min_length=1)],
    update: IncidentUpdate,
    current_user: Annotated[User, Depends(require_analyst)],
) -> Incident:
    """Update an incident's fields (status, severity, assignee, etc.)."""
    try:
        inc = IncidentService.update(incident_id, update)
        if not inc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        logger.info("Incident %s updated by user %s", clean_inc_id, clean_user_id)
        await WebhookService.fire(WebhookEventType.INCIDENT_UPDATED, inc.model_dump())

        if update.false_positive:
            await WebhookService.fire(WebhookEventType.FALSE_POSITIVE_FLAGGED, inc.model_dump())

        return inc
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        logger.exception("Failed to update incident %s", clean_inc_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Update failed")


@router.post(
    "/{incident_id}/comments",
    response_model=Incident,
    summary="Add a comment to an incident",
)
async def add_comment(
    incident_id: Annotated[str, Path(min_length=1)],
    body: IncidentCommentCreate,
    current_user: Annotated[User, Depends(require_auth)],
) -> Incident:
    """Add a comment to an incident. Users can comment on their own incidents."""
    inc = IncidentService.get(incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role == UserRole.USER and inc.reporter_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        updated = IncidentService.add_comment(
            incident_id,
            body,
            author_id=current_user.id,
            author_name=current_user.full_name,
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        logger.info("Comment added to incident %s by user %s", clean_inc_id, clean_user_id)
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        logger.exception("Failed to add comment to incident %s", clean_inc_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to add comment")


@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an incident",
    description="Analyst+ only.",
)
async def delete_incident(
    incident_id: Annotated[str, Path(min_length=1)],
    _: Annotated[User, Depends(require_analyst)],
) -> None:
    """Delete an incident permanently (analyst+ only)."""
    try:
        if not IncidentService.delete(incident_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        logger.info("Incident %s deleted", clean_inc_id)
    except Exception as e:
        clean_inc_id = str(incident_id).replace("\n", "").replace("\r", "")
        logger.exception("Failed to delete incident %s", clean_inc_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Deletion failed")