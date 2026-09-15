"""Step description shared by the guided-setup flows.

The prompting itself lives in cli/init_cmd.py and cli/setup.py; this module
only carries the shape a step is described with.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal


@dataclass
class SetupStep:
    """One step in the setup flow."""

    name: str
    description: str
    mode: Literal["automated", "guided"]
    execute: Callable  # runs automation (automated) or prints instructions (guided)
    validate: Callable  # verifies the step succeeded (both modes)
