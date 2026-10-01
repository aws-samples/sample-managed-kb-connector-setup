"""Resolve what a command operates on: connector, config, state, region, clients.

`resolve_context` turns a command's inputs into a `CommandContext`. Precedence:

* **Region**: explicit argument, then the region recorded in state, then config.
  State records where the resources are; config may have been edited since.
  Setup uses config instead and checks it against state
  (`cli.setup._record_region`).
* **Profile**: explicit argument, then config. State does not record one.
* **Target**: state, then config. Setup records the config target in state on
  every run.

Sessions and targets are built on first use through factories. Commands that
make no AWS call build neither, and tests pass fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kb_connector.core.config import ConnectorConfig, ToolConfig, load_config
from kb_connector.core.errors import ConfigError
from kb_connector.core.state import ConnectorState, StateFile, load_state, save_state

# Synthetic connector name for a command run against explicit --kb/--ds ids
# with no connector configured.
DIRECT = "_direct"

SessionFactory = Callable[[str | None, str | None], Any]
TargetFactory = Callable[..., Any]


def default_session_factory(region: str | None, profile: str | None) -> Any:
    """Build a boto3 Session. Imported lazily so --help and tests don't pay for it."""
    import boto3
    return boto3.Session(region_name=region, profile_name=profile)


def default_target_factory(
    *, session: Any, region: str | None, target: str | None = None
) -> Any:
    """Build the control-plane target. None means the default (Bedrock)."""
    from kb_connector.targets import get_target
    return get_target(target, session=session, region=region)


@dataclass
class CommandContext:
    """Everything a command needs to know about the connector it acts on."""

    config: ToolConfig
    state_file: StateFile
    state_path: str | None
    name: str
    # None for DIRECT, and for a connector that exists only in state.
    cfg: ConnectorConfig | None
    # None when state records nothing for this connector.
    cs: ConnectorState | None
    region: str | None
    profile: str | None
    target_name: str | None
    session_factory: SessionFactory = field(default=default_session_factory, repr=False)
    target_factory: TargetFactory = field(default=default_target_factory, repr=False)
    _session: Any = field(default=None, repr=False)
    _target: Any = field(default=None, repr=False)

    @property
    def is_direct(self) -> bool:
        return self.name == DIRECT

    def require_region(self, message: str | None = None) -> str:
        """Return the region, or raise if none was resolved."""
        if not self.region:
            raise ConfigError(
                message or "No region available. Pass region or set it in config."
            )
        return self.region

    def session(self) -> Any:
        """The AWS session for this command, built on first use."""
        if self._session is None:
            self._session = self.session_factory(self.region, self.profile)
        return self._session

    def target(self) -> Any:
        """The control-plane target for this command, built on first use."""
        if self._target is None:
            self._target = self.target_factory(
                session=self.session(), region=self.region, target=self.target_name
            )
        return self._target

    def ensure_state(self) -> ConnectorState:
        """Return this connector's state entry, creating an empty one if absent."""
        if self.cs is None:
            self.cs = self.state_file.get(self.name)
        return self.cs

    def save(self) -> str:
        """Persist this connector's state entry; return the file path.

        A DIRECT context has no entry to persist and writes nothing.
        """
        if self.is_direct or self.cs is None:
            return ""
        self.state_file.set(self.name, self.cs)
        return save_state(self.state_file, self.state_path)


def resolve_connector_name(
    config: ToolConfig,
    connector_name: str | None,
    *,
    direct_ok: bool = False,
) -> str:
    """Pick the connector to act on.

    An explicit name wins. With none, the only configured connector is used.
    `direct_ok` permits DIRECT when nothing is configured, for commands given
    explicit resource ids.
    """
    if connector_name:
        return connector_name
    names = config.connector_names()
    if len(names) == 1:
        return names[0]
    if not names:
        if direct_ok:
            return DIRECT
        raise ConfigError(
            "No connectors configured. Run 'kb-connector init' or pass a connector name."
        )
    raise ConfigError(
        f"Multiple connectors configured ({', '.join(names)}). Specify one."
    )


def resolve_context(
    connector_name: str | None = None,
    *,
    region: str | None = None,
    profile: str | None = None,
    config_path: str | None = None,
    state_path: str | None = None,
    direct_ok: bool = False,
    strict_config: bool = True,
    session_factory: SessionFactory | None = None,
    target_factory: TargetFactory | None = None,
) -> CommandContext:
    """Build the context for one command invocation.

    `strict_config=False` tolerates a connector entry that fails to resolve,
    treating it as absent. Teardown uses it: a broken config entry must not
    block cleaning up resources that state already tracks.
    """
    config = load_config(config_path)
    state_file = load_state(state_path)
    name = resolve_connector_name(config, connector_name, direct_ok=direct_ok)

    cfg: ConnectorConfig | None = None
    if name != DIRECT and name in config.connector_names():
        overrides = {k: v for k, v in (("region", region), ("profile", profile)) if v}
        try:
            cfg = config.resolve_connector(name, cli_overrides=overrides)
        except ConfigError:
            if strict_config:
                raise
            cfg = None

    cs = state_file.connectors.get(name) if name != DIRECT else None

    return CommandContext(
        config=config,
        state_file=state_file,
        state_path=state_path,
        name=name,
        cfg=cfg,
        cs=cs,
        region=region or (cs.region if cs else None) or (cfg.region if cfg else None),
        profile=profile or (cfg.profile if cfg else None),
        target_name=(cs.target if cs else None) or (cfg.target if cfg else None),
        session_factory=session_factory or default_session_factory,
        target_factory=target_factory or default_target_factory,
    )
