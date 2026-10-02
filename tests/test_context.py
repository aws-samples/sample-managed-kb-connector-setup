"""Tests for the command context: one precedence rule per resolved value."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kb_connector.context import DIRECT, resolve_context
from kb_connector.core.errors import ConfigError


def _project(tmp_path: Path, *, config: str, state: dict | None = None) -> dict:
    (tmp_path / "kb-connector.toml").write_text(config)
    state_path = tmp_path / "kb-connector.state.json"
    if state is not None:
        state_path.write_text(json.dumps({"connectors": state}))
    return {
        "config_path": str(tmp_path / "kb-connector.toml"),
        "state_path": str(state_path),
    }


_ONE = (
    '[defaults]\nregion = "eu-west-1"\nprofile = "cfg-profile"\n\n'
    '[connectors.c1]\ntype = "s3"\nbucket_name = "b"\n'
)


# --- region ------------------------------------------------------------------


def test_region_argument_wins(tmp_path):
    paths = _project(tmp_path, config=_ONE, state={"c1": {"region": "us-west-2"}})
    assert resolve_context("c1", region="ap-south-1", **paths).region == "ap-south-1"


def test_state_region_beats_config(tmp_path):
    """State records where the resources are; config may have been edited."""
    paths = _project(tmp_path, config=_ONE, state={"c1": {"region": "us-west-2"}})
    assert resolve_context("c1", **paths).region == "us-west-2"


def test_config_region_when_state_has_none(tmp_path):
    paths = _project(tmp_path, config=_ONE, state={"c1": {}})
    assert resolve_context("c1", **paths).region == "eu-west-1"


def test_require_region_raises_when_unresolved(tmp_path):
    paths = _project(tmp_path, config='[connectors.c1]\ntype = "s3"\n')
    ctx = resolve_context("c1", **paths)
    with pytest.raises(ConfigError, match="No region"):
        ctx.require_region()


# --- profile and target --------------------------------------------------------


def test_profile_argument_then_config(tmp_path):
    paths = _project(tmp_path, config=_ONE)
    assert resolve_context("c1", **paths).profile == "cfg-profile"
    assert resolve_context("c1", profile="arg", **paths).profile == "arg"


def test_state_target_beats_config(tmp_path):
    config = _ONE + 'target = "bmkb"\n'
    paths = _project(tmp_path, config=config, state={"c1": {"target": "quick"}})
    assert resolve_context("c1", **paths).target_name == "quick"


def test_config_target_when_state_has_none(tmp_path):
    """State files from before the target field still resolve."""
    paths = _project(tmp_path, config=_ONE, state={"c1": {}})
    assert resolve_context("c1", **paths).target_name == "bmkb"


# --- connector selection -------------------------------------------------------


def test_single_connector_is_picked(tmp_path):
    paths = _project(tmp_path, config=_ONE)
    assert resolve_context(None, **paths).name == "c1"


def test_multiple_connectors_require_a_name(tmp_path):
    paths = _project(
        tmp_path, config=_ONE + '\n[connectors.c2]\ntype = "s3"\nbucket_name = "b"\n'
    )
    with pytest.raises(ConfigError, match="Multiple connectors"):
        resolve_context(None, **paths)


def test_direct_only_when_permitted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="No connectors configured"):
        resolve_context(None, state_path=str(tmp_path / "s.json"))
    ctx = resolve_context(None, state_path=str(tmp_path / "s.json"), direct_ok=True)
    assert ctx.name == DIRECT and ctx.cfg is None and ctx.cs is None


def test_state_only_connector_resolves_without_config(tmp_path):
    """Teardown and monitor must still reach a connector removed from config."""
    paths = _project(tmp_path, config=_ONE, state={"gone": {"region": "us-west-2"}})
    ctx = resolve_context("gone", **paths)
    assert ctx.cfg is None and ctx.region == "us-west-2"


def test_broken_config_entry_is_tolerated_only_when_asked(tmp_path):
    bad = '[connectors.c1]\ntype = "s3"\ntarget = "nope"\n'
    paths = _project(tmp_path, config=bad, state={"c1": {"region": "us-west-2"}})
    with pytest.raises(ConfigError):
        resolve_context("c1", **paths)
    ctx = resolve_context("c1", strict_config=False, **paths)
    assert ctx.cfg is None and ctx.region == "us-west-2"


# --- laziness and persistence --------------------------------------------------


def test_session_and_target_are_built_once_on_first_use(tmp_path):
    paths = _project(tmp_path, config=_ONE)
    sessions: list = []
    targets: list = []
    ctx = resolve_context(
        "c1", **paths,
        session_factory=lambda r, p: sessions.append((r, p)) or object(),
        target_factory=lambda **kw: targets.append(kw) or object(),
    )
    assert sessions == [] and targets == []
    first = ctx.target()
    assert ctx.target() is first
    assert sessions == [("eu-west-1", "cfg-profile")]
    assert targets[0]["target"] == "bmkb" and targets[0]["region"] == "eu-west-1"


def test_save_writes_this_entry_and_keeps_others(tmp_path):
    paths = _project(
        tmp_path, config=_ONE,
        state={"c1": {"region": "us-west-2"}, "other": {"region": "eu-west-1"}},
    )
    ctx = resolve_context("c1", **paths)
    ctx.cs.last_ingestion_job_id = "JOB-1"
    ctx.save()
    saved = json.loads(Path(paths["state_path"]).read_text())["connectors"]
    assert saved["c1"]["last_ingestion_job_id"] == "JOB-1"
    assert saved["other"]["region"] == "eu-west-1"


def test_direct_context_never_writes_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state_path = tmp_path / "s.json"
    ctx = resolve_context(None, state_path=str(state_path), direct_ok=True)
    assert ctx.save() == ""
    assert not state_path.exists()
