"""Tests for `import entra help` / `acquire entra help` / `export entra help`.

The `import entra` menu used to reject `help` / `--help` / `-h` as unknown
subcommands, and its listing showed only import methods (browserdump,
roadtools, JWTs, cookies) — leaving operators who wanted a fresh token
staring at a wall of import-existing-artifact options with no pointer at
`acquire entra device_code` / `interactive` / `ropc`.

ANTI-GAMIFICATION: if the help subcommand regresses or the import usage
stops mentioning `acquire entra`, these tests fail.
"""
from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock

from rich.console import Console

from quantum_mechanic.shell import commands_entra as ce


def _capture(fn, args) -> str:
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        fn(MagicMock(), args)
    finally:
        ce.console = orig
    return buf.getvalue()


def test_import_entra_help_prints_usage_and_does_not_error():
    """OUTCOME: `import entra help` prints usage, no 'Unknown subcommand' line."""
    out = _capture(ce.import_entra, ["help"])
    assert "Usage: import entra" in out
    assert "Unknown subcommand" not in out


def test_import_entra_dashes_help_variants_all_work():
    """OUTCOME: --help, -h, ? all print usage."""
    for variant in ["--help", "-h", "?"]:
        out = _capture(ce.import_entra, [variant])
        assert "Usage: import entra" in out, f"{variant} did not print usage"
        assert "Unknown subcommand" not in out, f"{variant} was rejected as unknown"


def test_import_entra_usage_cross_references_acquire_entra():
    """OUTCOME: The import usage tells operators about `acquire entra` for
    fresh authentication — that's the #1 confusion this fix targets."""
    out = _capture(ce.import_entra, [])  # empty args also prints usage
    assert "acquire entra" in out
    assert "device_code" in out
    assert "interactive" in out


def test_import_entra_usage_mentions_browser_cdp():
    """OUTCOME: import usage shows the browser-assisted CDP path."""
    out = _capture(ce.import_entra, [])
    assert "browser_cdp" in out


def test_acquire_entra_help_prints_usage():
    out = _capture(ce.acquire_entra, ["help"])
    assert "Usage: acquire entra" in out
    assert "Unknown subcommand" not in out


def test_export_entra_help_prints_usage():
    out = _capture(ce.export_entra, ["help"])
    assert "Usage: export entra" in out
    assert "Unknown subcommand" not in out


def test_import_entra_unknown_subcommand_still_errors():
    """OUTCOME: `import entra bogus` still errors — help variants are the
    only strings we treat as help; genuine typos still surface as errors."""
    out = _capture(ce.import_entra, ["bogus"])
    assert "Unknown subcommand" in out
