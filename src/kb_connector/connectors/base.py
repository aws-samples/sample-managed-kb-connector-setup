"""ConnectorSpec interface — each connector implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Literal

from kb_connector.interactive import SetupStep


@dataclass
class ConfigField:
    """Declares a configuration field for a connector."""

    name: str
    required: bool = True
    type: type = str
    default: Any = None
    prompt: str | None = None
    warning: str | None = None
    required_if: str | None = None  # conditionally required based on another field


@dataclass
class DiagnosticCheck:
    """A connector-specific diagnostic check beyond the shared core."""

    name: str
    description: str
    execute: Callable
    side: Literal["source", "aws", "shared"] = "shared"


class ConnectorSpec(ABC):
    """Each connector implements this to declare its setup + config shape."""

    connector_type: str  # "SHAREPOINT", "WEB", etc.
    provider: str | None  # "microsoft", "google", "atlassian", None

    @abstractmethod
    def setup_steps(self, config: dict) -> list[SetupStep]:
        """Ordered setup steps. Each is automated or guided."""
        ...

    @abstractmethod
    def build_connector_params(self, config: dict, state: dict) -> dict:
        """Build the connectorParameters JSON body."""
        ...

    @abstractmethod
    def build_secret_body(self, config: dict, state: dict) -> dict | None:
        """Build the Secrets Manager secret JSON. None if no secret needed."""
        ...

    def config_fields(self) -> list[ConfigField]:
        """Connector-specific config fields for init prompts."""
        return []

    def diagnose_hints(self) -> list[DiagnosticCheck]:
        """Connector-specific diagnostic checks beyond the shared core."""
        return []
