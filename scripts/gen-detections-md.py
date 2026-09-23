#!/usr/bin/env python3
"""Regenerate docs/18-all-detections.md from checks/*.toml."""
from __future__ import annotations

import tomllib
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
OUT = ROOT / "docs" / "18-all-detections.md"

TYPE_ORDER = [
    "process",
    "file",
    "user",
    "directory",
    "log",
    "policy",
    "incident",
    "recon",
    "custom",
]
TYPE_TITLES = {
    "process": "Process (RM-PROC)",
    "file": "File (RM-FILE)",
    "user": "User / credentials (RM-USER, RM-CRED)",
    "directory": "Directory (RM-DIR)",
    "log": "Log (RM-LOG)",
    "policy": "Policy (RM-POL)",
    "incident": "Incident / correlation (RM-INC)",
    "recon": "Recon",
    "custom": "Custom",
}


def main() -> None:
    rows: list[dict] = []
    for p in sorted(CHECKS.glob("RM-*.toml")):
        d = tomllib.loads(p.read_text())
        d["_file"] = p.name
        rows.append(d)

    by_type: dict[str, list] = defaultdict(list)
    for r in rows:
        by_type[r.get("type", "?")].append(r)

    lines: list[str] = []
    lines.append("# RustMite — Complete Detection Catalog")
    lines.append("")
    lines.append(
        f"> Auto-generated from `checks/*.toml` on {date.today().isoformat()}."
    )
    lines.append(
        f"> **{len(rows)}** check manifests. Regenerate: `python3 scripts/gen-detections-md.py`."
    )
    lines.append("")
    lines.append(
        "Source of truth for operators and LLM agents. Seed overview also in "
        "[`11-detection-catalog.md`](11-detection-catalog.md); module algorithms in "
        "[`06-detection-modules.md`](06-detection-modules.md)."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Type | Count | Enabled |")
    lines.append("|---|---:|---:|")
    for t in TYPE_ORDER + sorted(set(by_type) - set(TYPE_ORDER)):
        items = by_type.get(t, [])
        if not items:
            continue
        en = sum(1 for i in items if i.get("enabled", True))
        lines.append(f"| {TYPE_TITLES.get(t, t)} | {len(items)} | {en} |")
    enabled_total = sum(1 for r in rows if r.get("enabled", True))
    lines.append(f"| **Total** | **{len(rows)}** | **{enabled_total}** |")
    lines.append("")
    lines.append("## Index")
    lines.append("")
    for r in rows:
        en = "✓" if r.get("enabled", True) else "○"
        lines.append(f"- [{en}] [`{r['id']}`](#{r['id'].lower()}) — {r.get('name', '')}")
    lines.append("")

    for t in TYPE_ORDER + sorted(set(by_type) - set(TYPE_ORDER)):
        items = by_type.get(t, [])
        if not items:
            continue
        lines.append(f"## {TYPE_TITLES.get(t, t)}")
        lines.append("")
        for r in items:
            rid = r["id"]
            lines.append(f"### {rid}")
            lines.append("")
            lines.append("| | |")
            lines.append("|---|---|")
            lines.append(f"| **Name** | {r.get('name', '')} |")
            lines.append(
                f"| **File** | [`checks/{r['_file']}`](../checks/{r['_file']}) |"
            )
            lines.append(f"| **Type** | `{r.get('type', '')}` |")
            lines.append(f"| **Severity** | {r.get('severity', '')} |")
            lines.append(f"| **Confidence** | {r.get('confidence', '')} |")
            lines.append(f"| **Enabled** | {r.get('enabled', True)} |")
            lines.append(f"| **Cost** | {r.get('cost', '')} |")
            lines.append(f"| **Match** | `{r.get('match', '')}` |")
            cols = r.get("collectors") or []
            if cols:
                lines.append(
                    f"| **Collectors** | {', '.join('`' + c + '`' for c in cols)} |"
                )
            attack = r.get("attack") or []
            if attack:
                lines.append(f"| **ATT&CK** | {', '.join(attack)} |")
            lines.append("")
            lines.append(f"**Title:** {r.get('title', '')}")
            lines.append("")
            if r.get("rationale"):
                lines.append(f"**Rationale:** {r['rationale']}")
                lines.append("")
            if r.get("false_positives"):
                lines.append(f"**False positives:** {r['false_positives']}")
                lines.append("")
            refs = r.get("references") or []
            if refs:
                lines.append("**References:**")
                for ref in refs:
                    lines.append(f"- {ref}")
                lines.append("")
            where = (r.get("where") or "").strip()
            lines.append("```")
            lines.append(where)
            lines.append("```")
            lines.append("")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(rows)} checks)")


if __name__ == "__main__":
    main()
