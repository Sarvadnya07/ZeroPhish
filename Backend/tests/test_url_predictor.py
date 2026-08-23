"""
Unit tests for Backend/ml/url_predictor.py.
Tests URLBERT, ONNX, and Mock predictors with deterministic mocking.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import ml.url_predictor as url_ml_mod
from ml.url_predictor import (
    MockURLPredictor,
    ONNXURLPredictor,
    URLBERTPredictor,
    URLPredictionResult,
    get_onnx_url_predictor,
    get_urlbert_predictor,
)


@pytest.fixture(autouse=True)
def reset_url_ml_singletons():
    url_ml_mod._urlbert_instance = None
    url_ml_mod._onnx_url_instance = None
    yield
    url_ml_mod._urlbert_instance = None
    url_ml_mod._onnx_url_instance = None


@pytest.mark.asyncio
async def test_mock_url_predictor():
    predictor = MockURLPredictor()
    assert predictor.is_loaded() is True

    # Empty URL
    res_empty = await predictor.predict("")
    assert res_empty.score == 0.0
    assert res_empty.label == "safe"

    # Phishing URL
    res_phish = await predictor.predict("http://paypa1-account-verify.com/login")
    assert res_phish.score >= 90.0
    assert res_phish.label == "phishing"

    # Suspicious URL
    res_susp = await predictor.predict("http://warning-service.com/update")
    assert 30.0 <= res_susp.score <= 70.0
    assert res_susp.label == "suspicious"

    # Safe URL
    res_safe = await predictor.predict("https://www.google.com/search")
    assert res_safe.score < 30.0
    assert res_safe.label == "safe"


@pytest.mark.asyncio
async def test_urlbert_predictor_load_and_predict():
    mock_tok = MagicMock()
    mock_tok.return_value = {"input_ids": MagicMock()}

    mock_outputs = MagicMock()
    mock_model = MagicMock()
    mock_model.return_value = mock_outputs

    mock_torch = MagicMock()
    mock_probs = MagicMock()
    # Logits yield [safe: 0.05, phishing: 0.95]
    mock_probs.cpu().numpy.return_value = [[0.05, 0.95]]
    mock_torch.softmax.return_value = mock_probs

    mock_tok_cls = MagicMock()
    mock_tok_cls.from_pretrained.return_value = mock_tok
    mock_model_cls = MagicMock()
    mock_model_cls.from_pretrained.return_value = mock_model

    with (
        patch.object(url_ml_mod, "TRANSFORMERS_AVAILABLE", True),
        patch.object(url_ml_mod, "AutoTokenizer", mock_tok_cls),
        patch.object(url_ml_mod, "AutoModelForSequenceClassification", mock_model_cls),
        patch.object(url_ml_mod, "torch", mock_torch),
    ):
        predictor = URLBERTPredictor(model_name="test-urlbert")
        loaded = await predictor.load_model()
        assert loaded is True
        assert predictor.is_loaded() is True

        res = await predictor.predict("http://evil-credential-steal.xyz/login")
        assert res.score >= 90.0
        assert res.label == "phishing"
        assert res.fallback_used is False


@pytest.mark.asyncio
async def test_urlbert_predictor_timeout_handling():
    predictor = URLBERTPredictor(model_name="test-urlbert", inference_timeout=0.01)
    predictor._loaded = True

    async def mock_wait_for(fut, timeout):
        if asyncio.iscoroutine(fut):
            fut.close()
        raise asyncio.TimeoutError()

    with patch("asyncio.wait_for", side_effect=mock_wait_for):
        res = await predictor.predict("http://slow-url.com")
        assert res.score == 50.0
        assert res.label == "unknown"
        assert res.fallback_used is True
        assert res.error == "Timeout"


@pytest.mark.asyncio
async def test_urlbert_predictor_unloaded_fallback():
    predictor = URLBERTPredictor(model_name="test-urlbert")
    with patch.object(predictor, "load_model", return_value=False):
        res = await predictor.predict("http://example.com")
        assert res.score == 50.0
        assert res.label == "unknown"
        assert res.fallback_used is True


@pytest.mark.asyncio
async def test_onnx_url_predictor_mocked():
    mock_session = MagicMock()
    mock_input = MagicMock()
    mock_input.name = "inputs"
    mock_session.get_inputs.return_value = [mock_input]
    # Return probabilities dictionary with 88% phishing
    mock_session.run.return_value = [None, [{0: 0.12, 1: 0.88}]]

    predictor = ONNXURLPredictor(model_path="dummy.onnx")
    predictor.session = mock_session
    predictor._loaded = True

    res = await predictor.predict("http://phishing-site.top/verify")
    assert res.score == 88.0
    assert res.label == "phishing"
    assert res.fallback_used is False


@pytest.mark.asyncio
async def test_onnx_url_predictor_missing_file():
    predictor = ONNXURLPredictor(model_path="./nonexistent_model.onnx")
    loaded = await predictor.load_model()
    assert loaded is False
    assert predictor.is_loaded() is False

    res = await predictor.predict("http://example.com")
    assert res.score == 50.0
    assert res.fallback_used is True
