"""Owner-only file writes for tool output.

Nothing this tool writes to disk contains a secret value — that is enforced
structurally (see core/state.py). What these files do contain is a precise map
of the environment: Entra tenant and application ids, AWS account ids, role and
secret ARNs, knowledge base ids, and for probe runs the full data-source
configuration and retrieved document excerpts.

That is reconnaissance material. On a shared host or a build agent, the default
umask leaves it world-readable, so every file the tool creates goes through this
module and lands with mode 0600.

The atomic writers also avoid the truncate-then-write window: a crash midway
through `save_state` would otherwise leave a half-written state file, and
`load_state` treats an unparseable state file as empty — which silently
un-tracks every resource the tool has created.

Prefer `atomic_write_json` / `atomic_write_bytes` over `open_owner_only`.
The atomic writers create their temp file with `O_EXCL` inside the destination
directory, so they never follow a symlink and never expose a partial file.
`open_owner_only` exists for callers that must stream (probe's events.jsonl)
and cannot buffer the whole payload; it opens the destination path directly,
which is only safe because the paths involved are operator-chosen output
directories rather than shared locations.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from typing import IO, Any

OWNER_ONLY = 0o600


def atomic_write_bytes(path: str, payload: bytes) -> str:
    """Write `payload` to `path` atomically, mode 0600. Returns the path.

    The temp file is created by `mkstemp` inside the destination directory, so
    it is created 0600 with O_EXCL and the final `os.replace` is a
    same-filesystem rename — atomic on POSIX and on Windows. `fchmod` operates
    on the descriptor rather than the path, so there is no window in which the
    content exists at looser permissions and no path to race.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".kbc-", suffix=".tmp")
    try:
        os.fchmod(fd, OWNER_ONLY)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            # Durability, not just atomicity: os.replace orders the rename but
            # not the data behind it, so a host-level power loss can otherwise
            # leave the new name pointing at unwritten blocks.
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        # Never leave a stray temp file holding environment detail behind.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # os.replace preserves the temp file's mode, but a pre-existing target may
    # have had looser permissions on some platforms. Re-assert.
    _restrict(path)
    return path


def atomic_write_json(path: str, data: Any, *, indent: int = 2, sort_keys: bool = False) -> str:
    """Write JSON to `path` atomically, mode 0600. Returns the path."""
    text = json.dumps(data, indent=indent, sort_keys=sort_keys, default=str) + "\n"
    return atomic_write_bytes(path, text.encode("utf-8"))


def open_owner_only(path: str, mode: str = "w") -> IO[Any]:
    """Open a file for writing with mode 0600 applied before any content lands.

    For callers that must stream rather than serialize in one shot (probe's
    events.jsonl). Prefer `atomic_write_bytes` or `atomic_write_json` where the
    whole payload can be buffered — they are atomic and cannot follow a symlink.

    O_NOFOLLOW is set so an existing symlink at `path` is refused rather than
    written through: the mode argument to `os.open` applies only when the file
    is created, so following a link would write content into an
    attacker-chosen destination at whatever permissions it already had.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, OWNER_ONLY)
    try:
        # Re-assert for the pre-existing-file case, where the mode argument to
        # os.open is ignored. Raise rather than swallow: the caller asked for an
        # owner-only file and is about to write environment detail into it.
        os.fchmod(fd, OWNER_ONLY)
    except OSError:
        os.close(fd)
        raise
    if mode.endswith("b"):
        return os.fdopen(fd, mode)
    return os.fdopen(fd, mode, encoding="utf-8")


def restrict_existing(path: str) -> None:
    """Tighten an existing file to 0600, ignoring absence."""
    _restrict(path)


def _restrict(path: str) -> None:
    try:
        os.chmod(path, OWNER_ONLY)
    except OSError:  # pragma: no cover - best effort on exotic filesystems
        pass


def describe_mode(path: str) -> str:
    """Return a file's permission bits as an octal string, for diagnostics."""
    return oct(stat.S_IMODE(os.stat(path).st_mode))
