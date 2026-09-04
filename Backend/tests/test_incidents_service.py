import pytest
from incidents.models import (
    IncidentCreate,
    IncidentUpdate,
    IncidentCommentCreate,
    IncidentSeverity,
    IncidentStatus,
)
from incidents.service import IncidentService


def test_incident_lifecycle():
    data = IncidentCreate(
        title="Suspicious Email",
        description="User reported phishing link",
        severity=IncidentSeverity.HIGH,
        reporter_email="victim@example.com",
    )
    inc = IncidentService.create(data, reporter_id="user-123\nINJECT")
    assert inc.id is not None
    assert inc.severity == IncidentSeverity.HIGH

    update = IncidentUpdate(status=IncidentStatus.IN_PROGRESS)
    updated = IncidentService.update(inc.id, update)
    assert updated is not None
    assert updated.status == IncidentStatus.IN_PROGRESS

    comment_data = IncidentCommentCreate(body="Analyzing payload")
    commented = IncidentService.add_comment(
        inc.id, comment_data, author_id="user-789\r\nINJECT", author_name="Alice"
    )
    assert commented is not None
    assert len(commented.comments) >= 1

    stats = IncidentService.stats()
    assert isinstance(stats, dict)

    deleted = IncidentService.delete(inc.id)
    assert deleted is True
    assert IncidentService.get(inc.id) is None
