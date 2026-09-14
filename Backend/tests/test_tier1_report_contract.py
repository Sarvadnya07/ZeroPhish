"""
CODEQUALITY-03: Behavioral regression validation for the /tier1/report contract.

Before CODEQUALITY-02 (R-4), the endpoint accepted `Dict[str, Any]` — every
JSON body was accepted verbatim and broadcast as-is. These characterization
tests pin that contract against the typed model: any payload the old endpoint
accepted must still be accepted with identical broadcast content.

Rationale for each case:
- {}                          — old endpoint accepted any dict, including empty.
- unknown extra fields        — old endpoint passed them through; must persist
                                through model round-trip into /tier1/latest.
- None values                 — JSON nulls were accepted; must not crash.
- layers_completed bounds     — pre-existing values in the wild (e.g. 2) are
                                valid; the constraint documents the domain, and
                                out-of-range behavior is characterized so the
                                change from "accept anything" is explicit.
- non-dict bodies (list/str)  — FastAPI rejected these BEFORE the refactor too
                                (body parsing into a dict model failed with 422),
                                so 422 is the pre-existing contract, not a
                                regression introduced by the typed model.
"""

import pytest
from fastapi.testclient import TestClient

from gateway import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_latest_report():
    import gateway

    gateway._latest_tier1_report = None
    yield
    gateway._latest_tier1_report = None


def _post_report(client, payload):
    return client.post("/tier1/report", json=payload)


def _latest(client):
    return client.get("/tier1/latest")


class TestEmptyPayload:
    def test_empty_object_accepted_and_broadcast(self, client):
        """Old contract: any dict accepted. Empty dict must still be accepted."""
        resp = _post_report(client, {})
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"
        assert _latest(client).json() == {}


class TestExtraFieldsPreserved:
    def test_unknown_fields_round_trip_to_latest(self, client):
        """Extension sends vendor-specific fields; they must survive to consumers."""
        payload = {
            "scan_id": "x-1",
            "vendor_extension_field": {"nested": [1, 2, 3]},
            "ml_provider_meta": "urlbert-v4",
        }
        resp = _post_report(client, payload)
        assert resp.status_code == 200
        latest = _latest(client).json()
        assert latest["vendor_extension_field"] == {"nested": [1, 2, 3]}
        assert latest["ml_provider_meta"] == "urlbert-v4"
        assert latest["scan_id"] == "x-1"

    def test_known_fields_not_dropped(self, client):
        payload = {"scan_id": "k-1", "final_score": 87.5, "verdict": "CRITICAL"}
        resp = _post_report(client, payload)
        assert resp.status_code == 200
        latest = _latest(client).json()
        assert latest["final_score"] == 87.5
        assert latest["verdict"] == "CRITICAL"


class TestNullValues:
    def test_null_fields_accepted(self, client):
        """JSON nulls were valid Dict[str, Any] content before; must stay valid."""
        payload = {"scan_id": None, "final_score": None, "evidence": None}
        resp = _post_report(client, payload)
        assert resp.status_code == 200


class TestLayersCompletedBounds:
    def test_in_range_values_accepted(self, client):
        for value in (0, 1, 2, 3):
            resp = _post_report(client, {"scan_id": "lc", "layers_completed": value})
            assert resp.status_code == 200, f"layers_completed={value} rejected"

    def test_out_of_range_rejected_with_422(self, client):
        """
        Intentional narrowing: old endpoint accepted layers_completed=99.
        The 0-3 bound documents the domain (three analysis tiers). This test
        makes the narrowing explicit so it cannot pass as an accident.
        """
        resp = _post_report(client, {"scan_id": "lc", "layers_completed": 99})
        assert resp.status_code == 422


class TestNonDictBodies:
    def test_list_body_rejected_as_before(self, client):
        """Pre-refactor FastAPI also rejected non-object JSON bodies (422)."""
        resp = client.post("/tier1/report", json=["not", "a", "dict"])
        assert resp.status_code == 422

    def test_string_body_rejected_as_before(self, client):
        resp = client.post("/tier1/report", json="just a string")
        assert resp.status_code == 422


class TestNumericCoercion:
    def test_int_final_score_accepted(self, client):
        """Pydantic float coercion: ints were fine as dict values, still fine."""
        resp = _post_report(client, {"final_score": 90})
        assert resp.status_code == 200
