#!/usr/bin/env python3
"""
04_report.py — Fase 4: geração dos 3 outputs via Jinja2.
  - report.md       → análise priorizada por risco
  - burp_import.txt → URLs únicas para Burp Suite Load URLs
  - findings.json   → já gerado na fase 3, só valida existência
"""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("  [report] Jinja2 não disponível. Abortando.")
    sys.exit(1)

OUTPUT_DIR    = Path(os.environ["OUTPUT_DIR"])
TEMPLATES_DIR = Path(os.environ["TEMPLATES_DIR"])
FINDINGS_FILE = OUTPUT_DIR / "findings.json"
REPORT_FILE   = OUTPUT_DIR / "report.md"
BURP_FILE     = OUTPUT_DIR / "burp_import.txt"

if not FINDINGS_FILE.exists():
    print("  [report] findings.json não encontrado. A fase 3 rodou corretamente?")
    sys.exit(1)

findings = json.loads(FINDINGS_FILE.read_text())

env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=False
)

# ── report.md ─────────────────────────────────────────────────────────────────
template = env.get_template("report.md.j2")
rendered = template.render(
    findings=findings,
    generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    target=os.environ.get("TARGET", ""),
    program=os.environ.get("PROGRAM", ""),
    mode=os.environ.get("MODE", "moderate")
)
REPORT_FILE.write_text(rendered)
print(f"  [report] report.md → {REPORT_FILE}")

# ── burp_import.txt ───────────────────────────────────────────────────────────
# Todas as URLs únicas com score > 0 (CRITICAL + HIGH + MEDIUM)
urls = set()
for tier in ("critical", "high", "medium"):
    for ep in findings["endpoints"].get(tier, []):
        url = ep.get("endpoint", "")
        if url.startswith("http"):
            urls.add(url)

# Adiciona também as JS source URLs (para o Burp ver o contexto)
oos_file = OUTPUT_DIR / "out_of_scope_refs.txt"
# (não inclui out-of-scope refs no burp_import — jamais tocar ativamente)

BURP_FILE.write_text("\n".join(sorted(urls)) + "\n")
print(f"  [report] burp_import.txt → {BURP_FILE} ({len(urls)} URLs)")
print(f"  [report] findings.json   → {FINDINGS_FILE}")
