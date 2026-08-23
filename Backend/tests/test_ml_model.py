"""
Unit tests for tier_2/ml_model.py with mocked Hugging Face transformers.
Tests model loading, inference, error handling, timeout handling, and singleton lifecycle.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

import tier_2.ml_model as ml_mod
from tier_2.ml_model import PhishingMLModel, get_ml_model


@pytest.fixture(autouse=True)
def reset_ml_singleton():
    ml_mod._ml_model_instance = None
    yield
    ml_mod._ml_model_instance = None


@pytest.mark.asyncio
async def test_phishing_ml_model_load_success():
    """Test successful model and tokenizer initialization."""
    mock_tok = MagicMock()
    mock_model = MagicMock()
    mock_tok_cls = MagicMock()
    mock_tok_cls.from_pretrained.return_value = mock_tok
    mock_model_cls = MagicMock()
    mock_model_cls.from_pretrained.return_value = mock_model

    with patch.object(ml_mod, "TRANSFORMERS_AVAILABLE", True), \
         patch.object(ml_mod, "AutoTokenizer", mock_tok_cls), \
         patch.object(ml_mod, "AutoModelForSequenceClassification", mock_model_cls), \
         patch.object(ml_mod, "torch", MagicMock()):
        model = PhishingMLModel(model_name="test-model", inference_timeout=2)
        loaded = await model.load_model()

        assert loaded is True
        assert model.is_loaded() is True
        assert model.tokenizer is mock_tok
        assert model.model is mock_model

        # Repeated load returns True immediately
        assert await model.load_model() is True


@pytest.mark.asyncio
async def test_phishing_ml_model_load_failure():
    """Test handling of exception during model loading."""
    mock_tok_cls = MagicMock()
    mock_tok_cls.from_pretrained.side_effect = RuntimeError("Download error")

    with patch.object(ml_mod, "TRANSFORMERS_AVAILABLE", True), \
         patch.object(ml_mod, "AutoTokenizer", mock_tok_cls), \
         patch.object(ml_mod, "torch", MagicMock()):
        model = PhishingMLModel(model_name="test-model")
        loaded = await model.load_model()
        assert loaded is False
        assert model.is_loaded() is False


@pytest.mark.asyncio
async def test_phishing_ml_model_predict_phishing():
    """Test inference predicting phishing."""
    mock_tok = MagicMock()
    mock_tok.return_value = {"input_ids": MagicMock()}

    mock_outputs = MagicMock()
    mock_model = MagicMock()
    mock_model.return_value = mock_outputs

    mock_torch = MagicMock()
    mock_probs = MagicMock()
    mock_probs.cpu().numpy.return_value = [[0.1, 0.9]]
    mock_torch.softmax.return_value = mock_probs

    with patch.object(ml_mod, "TRANSFORMERS_AVAILABLE", True), \
         patch.object(ml_mod, "torch", mock_torch):
        model = PhishingMLModel(model_name="test-model")
        model.tokenizer = mock_tok
        model.model = mock_model
        model._loaded = True

        score, label = await model.predict("Urgent: your account is suspended! Click here.")
        assert score >= 70.0
        assert label == "phishing"


@pytest.mark.asyncio
async def test_phishing_ml_model_predict_safe():
    """Test inference predicting safe email."""
    mock_tok = MagicMock()
    mock_tok.return_value = {"input_ids": MagicMock()}

    mock_outputs = MagicMock()
    mock_model = MagicMock()
    mock_model.return_value = mock_outputs

    mock_torch = MagicMock()
    mock_probs = MagicMock()
    mock_probs.cpu().numpy.return_value = [[0.95, 0.05]]
    mock_torch.softmax.return_value = mock_probs

    with patch.object(ml_mod, "TRANSFORMERS_AVAILABLE", True), \
         patch.object(ml_mod, "torch", mock_torch):
        model = PhishingMLModel(model_name="test-model")
        model.tokenizer = mock_tok
        model.model = mock_model
        model._loaded = True

        score, label = await model.predict("Team meeting tomorrow at 10 AM.")
        assert score < 30.0
        assert label == "safe"


@pytest.mark.asyncio
async def test_phishing_ml_model_predict_timeout():
    """Test inference timeout handling."""
    model = PhishingMLModel(model_name="test-model", inference_timeout=0.01)
    model._loaded = True

    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
        score, label = await model.predict("Long running text")
        assert score == 50.0
        assert label == "timeout"


@pytest.mark.asyncio
async def test_phishing_ml_model_predict_unloaded_failure():
    """Test predict when model cannot be loaded."""
    model = PhishingMLModel(model_name="test-model")
    with patch.object(model, "load_model", return_value=False):
        score, label = await model.predict("Hello")
        assert score == 50.0
        assert label == "unknown"


@pytest.mark.asyncio
async def test_phishing_ml_model_unload():
    """Test model unload and cleanup."""
    model = PhishingMLModel(model_name="test-model")
    model._loaded = True
    model.tokenizer = MagicMock()
    model.model = MagicMock()

    await model.unload_model()
    assert model.is_loaded() is False
    assert model.model is None
    assert model.tokenizer is None
