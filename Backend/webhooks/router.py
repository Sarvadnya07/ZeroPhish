"""
Webhook FastAPI router — /webhooks/* endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from auth.middleware import require_admin, require_analyst, require_auth
from auth.models import User

from .models import WebhookSubscription, WebhookSubscriptionCreate
from .service import WebhookService

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("", response_model=WebhookSubscription, status_code=201)
async def create_subscription(
    data: WebhookSubscriptionCreate,
    current_user: User = Depends(require_analyst),
):
    try:
        return WebhookService.subscribe(data, owner_id=current_user.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[WebhookSubscription])
async def list_subscriptions(current_user: User = Depends(require_auth)):
    from auth.models import UserRole

    # Admins see all; others see only theirs
    owner = None if current_user.role == UserRole.ADMIN else current_user.id
    return WebhookService.list_subscriptions(owner_id=owner)


@router.get("/deliveries")
async def delivery_log(limit: int = 100, _: User = Depends(require_admin)):
    return WebhookService.delivery_log(limit=limit)


@router.get("/{sub_id}", response_model=WebhookSubscription)
async def get_subscription(sub_id: str, current_user: User = Depends(require_auth)):
    sub = WebhookService.get_subscription(sub_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    from auth.models import UserRole

    if current_user.role != UserRole.ADMIN and sub.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return sub


@router.delete("/{sub_id}", status_code=204)
async def delete_subscription(sub_id: str, current_user: User = Depends(require_auth)):
    from auth.models import UserRole

    owner = None if current_user.role == UserRole.ADMIN else current_user.id
    ok = WebhookService.unsubscribe(sub_id, owner_id=owner)
    if not ok:
        raise HTTPException(status_code=404, detail="Subscription not found or access denied")
