# ================================================================
# MODULE: quantum_mechanic.core.loot
# ----------------------------------------------------------------
# PURPOSE:   CloudFox-style loot writer.  After every successful
#            technique execution, drops two artifacts into the
#            workspace loot directory:
#
#              loot.csv   — one row per discovered asset, always
#                           includes an empty `notes` column so
#                           operators can annotate findings.
#
#              table.txt  — plain-text (no ANSI) version of the
#                           terminal table for sharing / diffing.
#
# OUTPUT PATH:
#   <workspace_db_dir>/loot/<tactic>/<technique_name>/
#
# DESIGN:
#   Each technique module declares two module-level constants:
#
#     LOOT_ITEMS_KEY: str | None
#       The key inside result.data that holds the list of items.
#       If None, result.data itself is treated as a single row.
#
#     LOOT_SCHEMA: list[tuple[str, str | None, str | None]]
#       Ordered (data_key, display_name, style) tuples.
#       display_name = None → column is always empty (e.g. "notes").
#
#   LootWriter dynamically imports the technique module to read
#   these constants — zero coupling required at the runner level.
#
#   CONTRACT:
#     - write() never raises.  All errors are logged.
#     - Existing loot is overwritten on every run to represent the latest state.
#     - File encoding is always UTF-8.
# ================================================================

from __future__ import annotations

import csv
import importlib
import io
import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from quantum_mechanic.core.runner import TechniqueResult

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Technique-id → Python module path mapping.
# Needed because technique_id uses "/" separators.
# ----------------------------------------------------------------
_TECHNIQUE_MODULE_BASE = "quantum_mechanic.techniques"


def _module_path(technique_id: str) -> str:
    """Convert 'discovery/enum_storage' → 'quantum_mechanic.techniques.discovery.enum_storage'."""
    return f"{_TECHNIQUE_MODULE_BASE}.{technique_id.replace('/', '.')}"


# ================================================================
# Public API
# ================================================================


class LootWriter:
    """Writes loot.csv and table.txt for a completed technique run."""

    def write(
        self,
        result: TechniqueResult,
        workspace_db_path: Path,
    ) -> Path | None:
        """Write loot artifacts for *result* and return the loot directory.

        Args:
            result:            The completed TechniqueResult (status='success').
            workspace_db_path: Path to the workspace .db file.  Loot is stored
                               as a sibling directory named after the workspace.

        Returns:
            Path to the loot directory, or None if writing failed / no schema.
        """
        try:
            return self._write(result, workspace_db_path)
        except Exception as exc:
            logger.warning("Loot write failed for %s: %s", result.technique_id, exc)
            return None

    # ----------------------------------------------------------------
    # Internal
    # ----------------------------------------------------------------

    def _write(
        self,
        result: TechniqueResult,
        workspace_db_path: Path,
    ) -> Path | None:
        schema, items_key = self._load_schema(result.technique_id)
        if schema is None:
            return None

        data = result.data
        if not data:
            return None

        loot_dir = self._loot_dir(workspace_db_path, result.technique_id)
        loot_dir.mkdir(parents=True, exist_ok=True)

        # Non-success runs must NOT emit CSV/table artifacts — that would
        # produce misleading empty loot dirs when the technique was actually
        # denied or errored. Instead, drop a _status.txt sentinel so operators
        # grepping loot dirs still see something. See spec.md §3.6.
        if result.status not in ("success", "partial"):
            self._write_status_sentinel(loot_dir, result)
            return loot_dir

        # --------------------------------------------------------
        # Check for global run note in params (passed via result)
        # --------------------------------------------------------
        # We need access to ctx.params, which isn't in TechniqueResult.
        # However, _handle_post_execution in runner.py ALREADY injected
        # it into dicts. For dataclasses, we do it in _extract_items below.
        # --------------------------------------------------------

        items = self._extract_items(data, items_key, result.technique_id, result.params)
        # Always write headers if they don't exist, even if items is empty
        self._write_csv(loot_dir / "loot.csv", schema, items)
        self._write_table(loot_dir / "table.txt", schema, items)

        # Partial runs get a note in the loot dir explaining why they may
        # be incomplete — the operator should re-run to close the gap.
        if result.status == "partial":
            self._write_status_sentinel(loot_dir, result)

        return loot_dir

    def _write_status_sentinel(self, loot_dir: Path, result: TechniqueResult) -> None:
        """Drop _status.txt describing why this run did not produce loot."""
        try:
            data = result.data if isinstance(result.data, dict) else {}
            lines = [
                f"technique: {result.technique_id}",
                f"status: {result.status}",
                f"provider: {result.provider}",
            ]
            if result.error:
                lines.append(f"error: {result.error}")
            elif data.get("error"):
                lines.append(f"error: {data['error']}")
            if data.get("required_scope"):
                lines.append(f"required_scope: {data['required_scope']}")
            if data.get("http_status"):
                lines.append(f"http_status: {data['http_status']}")
            (loot_dir / "_status.txt").write_text("\n".join(lines) + "\n")
        except Exception as exc:
            logger.debug("Failed to write _status.txt: %s", exc)

    def _load_schema(self, technique_id: str) -> tuple[list[tuple] | None, str | None]:
        """Import the technique module and read LOOT_SCHEMA / LOOT_ITEMS_KEY.

        Returns (schema, items_key) or (None, None) if the technique has no schema.
        """
        mod_path = _module_path(technique_id)
        try:
            mod = importlib.import_module(mod_path)
        except ImportError:
            logger.debug("Loot: cannot import %s — no loot written.", mod_path)
            return None, None

        schema = getattr(mod, "LOOT_SCHEMA", None)
        if schema is None:
            return None, None

        items_key = getattr(mod, "LOOT_ITEMS_KEY", None)
        return schema, items_key

    def _loot_dir(self, workspace_db_path: Path, technique_id: str) -> Path:
        """Build the loot output directory path.

        <workspace_db_path.parent>/<workspace_stem>/loot/<technique_id>/
        e.g. ~/.quantum_mechanic/workspaces/acme/loot/discovery/enum_storage/
        """
        ws_dir = workspace_db_path.parent / workspace_db_path.stem
        return ws_dir / "loot" / technique_id

    def _extract_items(
        self,
        data: Any,
        items_key: str | None,
        technique_id: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Pull the list of row-dicts from result.data.

        If items_key is None, data itself is the single row.
        Handles nested env-var flattening for serverless_env_harvest.
        """
        # 1. Convert dataclass to dict if needed
        if is_dataclass(data):
            data = asdict(data)

        # 2. Extract raw rows
        if items_key is None:
            # Single-row techniques (whoami, compute_identity_abuse, etc.)
            rows = [data] if isinstance(data, dict) else []
        else:
            raw = data.get(items_key, []) if isinstance(data, dict) else []

            # Special case: serverless_env_harvest flattening
            if technique_id == "credential_access/serverless_env_harvest":
                rows = []
                for fn in raw:
                    for ev in fn.get("env_vars", []):
                        rows.append(
                            {
                                "name": fn.get("name", ""),
                                "var_name": ev.get("name", ""),
                                "var_value": ev.get("value", ""),
                                "sensitivity": ev.get("sensitivity", ""),
                            }
                        )
            else:
                rows = [item for item in raw if isinstance(item, dict)]

        # 3. Inject global run note if provided via CLI
        run_note = params.get("_run_note") if params else None
        if run_note:
            for row in rows:
                row.setdefault("notes", run_note)

        return rows

    def _write_csv(
        self,
        path: Path,
        schema: list[tuple],
        items: list[dict],
    ) -> None:
        """Write rows to loot.csv, overwriting any existing file."""
        columns = [entry[0] for entry in schema]

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for item in items:
                row = {
                    key: "" if item.get(key) is None else str(item.get(key, "")) for key in columns
                }
                writer.writerow(row)

    def _write_table(
        self,
        path: Path,
        schema: list[tuple],
        items: list[dict],
    ) -> None:
        """Write a plain-text Rich table to table.txt (overwriting any existing file)."""
        from rich import box
        from rich.console import Console
        from rich.table import Table

        tbl = Table(box=box.ROUNDED, border_style="dim")
        for entry in schema:
            key = entry[0]
            label = entry[1]
            display = label if label else key.replace("_", " ").title()
            tbl.add_column(display)

        for item in items:
            row_vals = []
            for entry in schema:
                key = entry[0]
                label = entry[1]
                # Check both the key and a capitalized version for flexibility
                val = item.get(key) or item.get(key.capitalize())
                row_vals.append("" if val is None else str(val))
            tbl.add_row(*row_vals)

        buf = io.StringIO()
        plain_console = Console(
            file=buf, force_terminal=False, highlight=False, markup=False, width=120
        )
        plain_console.print(tbl)
        text = buf.getvalue()

        with path.open("w", encoding="utf-8") as fh:
            fh.write(text)


# Module-level singleton — callers import and use loot_writer.write(...)
loot_writer = LootWriter()
