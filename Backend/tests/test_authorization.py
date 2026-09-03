import pytest
from fastapi.testclient import TestClient

from auth.models import UserRole, UserStatus
from auth.service import AuthService, _users_by_clerk_id, _users_by_email, _users_by_id
from gateway import app
from incidents.service import _store as _incidents
from webhooks.service import _subscriptions


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    _users_by_id.clear()
    _users_by_email.clear()
    _users_by_clerk_id.clear()
    _incidents.clear()
    _subscriptions.clear()
    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    yield


@pytest.fixture
def client():
    return TestClient(app)


def create_user_and_token(client, role: UserRole = UserRole.USER) -> tuple[str, str]:
    import asyncio
    import random

    unique_suffix = f"{random.randint(1,10000)}_{role.value}"
    token = f"test_token_{unique_suffix}_{role.value}"
    user = asyncio.run(
        AuthService.get_or_create_user(
            clerk_user_id=f"user_clerk_{unique_suffix}",
            email=f"{unique_suffix}@example.com",
            full_name=f"Test {unique_suffix}",
            role=role,
        )
    )
    return user.id, token


def test_incident_comment_cross_user_denied(client):
    user_a_id, token_a = create_user_and_token(client, role=UserRole.USER)
    user_b_id, token_b = create_user_and_token(client, role=UserRole.USER)

    res = client.post(
        "/incidents",
        json={
            "title": "Phishing Incident",
            "description": "test",
            "subject": "Phishing",
            "sender": "bad@bad.com",
            "final_score": 10.0,
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    res_comment = client.post(
        f"/incidents/{inc_id}/comments",
        json={"body": "User B comment"},
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert res_comment.status_code in [403, 404]


def test_webhook_cross_user_unsubscribe_denied(client):
    user_a_id, token_a = create_user_and_token(client, role=UserRole.ANALYST)
    user_b_id, token_b = create_user_and_token(client, role=UserRole.USER)

    res = client.post(
        "/webhooks",
        json={
            "url": "http://example.com/webhook",
            "events": ["incident.created"],
            "secret": "test_secret",
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res.status_code == 201
    sub_id = res.json()["id"]

    res_del = client.delete(f"/webhooks/{sub_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert res_del.status_code in [403, 404]


def test_admin_route_requires_admin_role(client):
    _, token = create_user_and_token(client, role=UserRole.USER)
    res = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_analyst_cannot_access_admin_only_route(client):
    _, token = create_user_and_token(client, role=UserRole.ANALYST)
    res = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_user_cannot_update_own_role(client):
    _, token = create_user_and_token(client, role=UserRole.USER)
    res = client.patch(
        "/auth/me",
        json={"role": "admin", "full_name": "New Name"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["role"] == "user"
