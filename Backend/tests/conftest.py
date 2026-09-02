import sys
import pytest

if sys.platform == "win32":
    sys.modules.setdefault("torchvision", None)
    sys.modules.setdefault("torchvision.transforms", None)


@pytest.fixture(scope="session", autouse=True)
def reset_app_state():
    """Isolate tests that share the gateway app instance."""
    yield
