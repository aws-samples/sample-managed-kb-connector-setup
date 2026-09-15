"""Shared test fixtures.

The credential-shaped fixtures here generate their values at run time rather
than carrying literals. That is not ceremony: a credential-named assignment
whose right-hand side is a quoted literal is precisely the shape secret
scanners match, and a test file is not a good place to argue with one. Scanner
rulesets vary between tools and versions, so a literal one ruleset ignores
another will flag — and the finding lands in git history, where it outlives the
line that caused it.

Generating the value removes the pattern instead of suppressing the alert, and
it makes the assertions marginally stronger: a random value cannot collide
with unrelated text in a repr or a serialized file.
"""

from __future__ import annotations

import secrets

import pytest


def make_fixture_secret(label: str = "fixture") -> str:
    """Return a throwaway credential-shaped value, unique per call.

    `label` is prepended so a value that unexpectedly shows up in output is
    traceable back to the test that made it.
    """
    return f"{label}-{secrets.token_urlsafe(12)}"


@pytest.fixture
def fixture_secret() -> str:
    """A single throwaway secret value for one test."""
    return make_fixture_secret()


@pytest.fixture
def fixture_secret_factory():
    """Build several distinct throwaway secrets within one test."""
    return make_fixture_secret
