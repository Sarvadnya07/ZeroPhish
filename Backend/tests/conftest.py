import importlib.machinery
import sys
import types

import pytest


if sys.platform == "win32":
    def _ensure_stub_module(name: str, *, is_package: bool = False):
        existing = sys.modules.get(name)
        if existing is not None and getattr(existing, "__spec__", None) is not None:
            return existing

        module = types.ModuleType(name)
        module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, is_package=is_package)
        if is_package:
            module.__path__ = []
        sys.modules[name] = module
        return module

    tv = _ensure_stub_module("torchvision", is_package=True)
    tv_io = _ensure_stub_module("torchvision.io")
    tv_io.ImageReadMode = object
    tv_io.decode_image = lambda *a, **kw: None
    tv_tf = _ensure_stub_module("torchvision.transforms")
    tv_tf.InterpolationMode = types.SimpleNamespace(
        NEAREST_EXACT="nearest",
        BOX="box",
        BILINEAR="bilinear",
        HAMMING="hamming",
        BICUBIC="bicubic",
        LANCZOS="lanczos",
    )
    tv_tff = _ensure_stub_module("torchvision.transforms.functional")
    tv_tff.pil_to_tensor = lambda *a, **kw: None


@pytest.fixture(scope="session", autouse=True)
def reset_app_state():
    """Isolate tests that share the gateway app instance."""
    yield


def pytest_sessionfinish(session, exitstatus):
    session.config._exitstatus = exitstatus


def pytest_unconfigure(config):
    import os
    import sys
    sys.stdout.flush()
    sys.stderr.flush()
    exit_code = getattr(config, "_exitstatus", 0)
    os._exit(exit_code)
