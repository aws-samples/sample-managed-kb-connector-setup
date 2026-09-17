#!/usr/bin/env python3
"""Fail if a list, set, or dict literal contains implicitly concatenated strings.

Python concatenates adjacent string literals silently, so `["a" "b", "c"]` is a
two-element list and not a three-element one. At a glance that is
indistinguishable from a forgotten comma.

This matters here more than it would in most codebases: the lists in
core/provisioning.py hold IAM actions and policy resource ARNs. An element
merged into its neighbor by a missing comma does not raise — it produces a
policy with a resource ARN that does not exist, or an action list missing an
entry, and the failure shows up later as an opaque AccessDenied.

A parenthesized concatenation (`msg = ("a" "b")`, `help=("a" "b")`) is the
idiomatic unambiguous form and is not reported: there is no comma to omit. Only
`[`, `{` and their contents are checked.

Run:  python scripts/check_implicit_concat.py src tests
"""

from __future__ import annotations

import io
import pathlib
import sys
import token
import tokenize


def find_in_file(path: pathlib.Path) -> list[tuple[int, str]]:
    """Return (line number, source line) for each offending concatenation."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tokens = [
        t
        for t in tokenize.generate_tokens(io.StringIO(source).readline)
        if t.type
        not in (
            token.NL,
            token.NEWLINE,
            token.COMMENT,
            token.INDENT,
            token.DEDENT,
        )
    ]

    # One entry per open bracket: True when it opens a collection literal.
    # A '(' is never treated as one, which is what exempts the parenthesized
    # form. Tuples written with parentheses inside a list are still covered by
    # the enclosing '['.
    bracket_is_collection: list[bool] = []
    found: list[tuple[int, str]] = []

    for index, tok in enumerate(tokens):
        if tok.type == token.OP and tok.string in "([{":
            bracket_is_collection.append(tok.string in "[{")
        elif tok.type == token.OP and tok.string in ")]}":
            if bracket_is_collection:
                bracket_is_collection.pop()
        elif tok.type == token.STRING:
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if (
                following is not None
                and following.type == token.STRING
                and bracket_is_collection
                and bracket_is_collection[-1]
            ):
                line_number = tok.start[0]
                found.append((line_number, lines[line_number - 1].strip()))

    return found


def main(argv: list[str]) -> int:
    roots = [pathlib.Path(a) for a in argv[1:]] or [pathlib.Path("src")]
    failures: list[str] = []

    for root in roots:
        if not root.exists():
            print(f"error: {root} does not exist", file=sys.stderr)
            return 2
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            for line_number, text in find_in_file(path):
                failures.append(f"{path}:{line_number}: {text}")

    if failures:
        print(
            "Implicitly concatenated strings inside a collection literal.\n"
            "If the concatenation is intended, bind it to a name or wrap it in\n"
            "parentheses outside the literal. If a comma is missing, add it.\n",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    scanned = ", ".join(str(r) for r in roots)
    print(f"ok: no implicit concatenation in collection literals ({scanned})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
