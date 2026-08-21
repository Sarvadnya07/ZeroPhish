import pytest

@pytest.fixture(scope="session", autouse=True)
def reset_app_state():
    """Isolate tests that share the gateway app instance."""
    yield
