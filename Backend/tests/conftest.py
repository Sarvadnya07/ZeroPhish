import importlib.machinery
import sys
import types

import pytest


if sys.platform == "win32":
    def _ensure_stub_module(name: str, *, is_package: bool = False):
        module = sys.modules.setdefault(name, types.ModuleType(name))
        if getattr(module, "__spec__", None) is None:
            module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, is_package=is_package)
            if is_package:
                module.__path__ = []
        return module

    _ensure_stub_module("torchvision", is_package=True)
    _ensure_stub_module("torchvision.transforms")


@pytest.fixture(scope="session", autouse=True)
def reset_app_state():
    """Isolate tests that share the gateway app instance."""
    yield
