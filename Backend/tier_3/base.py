"""
Tier 3 Provider Abstraction: Core Interfaces and Capabilities
=============================================================
Defines the provider-agnostic contracts for Tier 3 AI computation:
- ProviderCapabilities: Explicit runtime capability declarations
- ProviderRawResponse: Normalized raw output container
- AIProvider: Abstract Base Class for LLM providers
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    AUTH_ERROR = "AUTH_ERROR"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNAVAILABLE = "UNAVAILABLE"


class ProviderCapabilities(BaseModel):
    """
    Explicit capability declarations for each AI provider.
    Routing policy inspects these attributes to select eligible providers.
    """
    provider_id: str
    display_name: str
    text_analysis: bool = True
    structured_json: bool = True
    vision: bool = False
    streaming: bool = False
    tool_calling: bool = False
    max_context_tokens: int = 8192
    max_output_tokens: int = 1024
    local: bool = False
    estimated_latency_ms: int = 1000
    requires_auth: bool = True
    supported_models: List[str] = Field(default_factory=list)


@dataclass
class ProviderRawResponse:
    """
    Normalized raw output container before canonical schema validation.
    """
    provider_id: str
    model: str
    status: ProviderExecutionStatus
    raw_text: Optional[str] = None
    raw_json: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0
    error_message: Optional[str] = None
    http_status_code: Optional[int] = None
    token_usage: Dict[str, int] = field(default_factory=dict)


class AIProvider(ABC):
    """
    Abstract Base Class for Tier 3 AI Providers.
    All providers must implement this interface.
    """

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """Return declared capabilities of the provider."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the provider is configured and available for execution.
        Must return False if credentials are missing or endpoints unreachable.
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Lightweight asynchronous health probe."""
        pass

    @abstractmethod
    async def generate_analysis(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        timeout_sec: float = 2.5,
        **kwargs: Any
    ) -> ProviderRawResponse:
        """
        Execute raw generation against the provider.
        Returns normalized ProviderRawResponse. Must never raise unhandled transport
        exceptions; transport/timeout errors must be encapsulated in ProviderRawResponse.
        """
        pass

    async def generate_multimodal_analysis(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str,
        system_instruction: Optional[str] = None,
        timeout_sec: float = 3.5,
        **kwargs: Any,
    ) -> ProviderRawResponse:
        """
        Execute multimodal visual analysis with raw image bytes against the provider.
        Default implementation rejects if provider lacks vision capabilities.
        """
        return ProviderRawResponse(
            provider_id=self.capabilities.provider_id,
            model="unknown",
            status=ProviderExecutionStatus.INVALID_PAYLOAD,
            error_message=f"Provider {self.capabilities.provider_id} does not support multimodal vision.",
        )
