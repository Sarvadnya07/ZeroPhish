"""
Webhook FastAPI router — /webhooks/* endpoints.

Provides CRUD for subscriptions and delivery log access.
All endpoints are protected by RBAC (admin/analyst/user).
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from auth.middleware import require_admin, require_analyst, require_auth
from auth.models import User, UserRole

from .models import WebhookSubscription, WebhookSubscriptionCreate
from .service import WebhookService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post(
    "",
    response_model=WebhookSubscription,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new webhook subscription",
    description="Analysts and above can create subscriptions.",
)
async def create_subscription(
    data: WebhookSubscriptionCreate,
    current_user: User = Depends(require_analyst),
) -> WebhookSubscription:
    """
    Create a new webhook subscription.

    - URL is validated against SSRF protection.
    - A random secret is generated for HMAC signing.
    """
    try:
        return await WebhookService.subscribe(data, owner_id=current_user.id)
    except ValueError as e:
        logger.warning("Webhook creation failed for user %s: %s", current_user.id, e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error creating webhook for user %s", current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create subscription")


@router.get(
    "",
    response_model=List[WebhookSubscription],
    summary="List webhook subscriptions",
    description="Admins see all; regular users see only their own.",
)
async def list_subscriptions(
    current_user: User = Depends(require_auth),
) -> List[WebhookSubscription]:
    """List subscriptions accessible to the current user."""
    owner_id = None if current_user.role == UserRole.ADMIN else current_user.id
    return WebhookService.list_subscriptions(owner_id=owner_id)


@router.get(
    "/deliveries",
    response_model=List[dict],
    summary="Webhook delivery log",
    description="Admin only.",
)
async def delivery_log(
    limit: int = Query(100, ge=1, le=500, description="Number of entries to return"),
    _: User = Depends(require_admin),
) -> List[dict]:
    """Get recent webhook delivery logs (admin only)."""
    deliveries = WebhookService.delivery_log(limit=limit)
    # Convert to dict for safe serialisation
    return [d.model_dump() for d in deliveries]


@router.get(
    "/{sub_id}",
    response_model=WebhookSubscription,
    summary="Get a subscription by ID",
    description="Users can only access their own subscriptions; admins can access any.",
)
async def get_subscription(
    sub_id: str = Path(..., min_length=1, description="Subscription ID"),
    current_user: User = Depends(require_auth),
) -> WebhookSubscription:
    """Retrieve a single webhook subscription."""
    sub = WebhookService.get_subscription(sub_id)
    if not sub:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")

    if current_user.role != UserRole.ADMIN and sub.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return sub


@router.delete(
    "/{sub_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a subscription",
    description="Users can delete their own; admins can delete any.",
)
async def delete_subscription(
    sub_id: str = Path(..., min_length=1),
    current_user: User = Depends(require_auth),
) -> None:
    """Delete a webhook subscription."""
    owner_id = None if current_user.role == UserRole.ADMIN else current_user.id
    ok = await WebhookService.unsubscribe(sub_id, owner_id=owner_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found or access denied")
    logger.info("Subscription %s deleted by user %s", sub_id, current_user.id)