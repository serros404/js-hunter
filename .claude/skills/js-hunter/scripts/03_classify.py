#!/usr/bin/env python3
"""
03_classify.py — Fase 3: classificação e scoring de findings por risco IDOR/BAC.

Scoring model:
  Pattern HIGH match     → +3 pts
  Pattern MEDIUM match   → +1 pt
  Método DELETE/PUT/PATCH → +2 pts
  Aparece em 2+ JS files → +1 pt (confiança)
  JS minificado          → flag minified=True (não penaliza, é contexto)
  Secret CRITICAL        → risco próprio, não entra no score de endpoint
  Terceiro (CDN/analytics) → descartado (score=0)

Risk tiers finais:
  score >= 5  → CRITICAL
  score >= 3  → HIGH
  score >= 1  → MEDIUM
  score == 0  → LOW (mantido no JSON, omitido do report principal)
"""

from __future__ import annotations
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

RAW_DIR    = Path(os.environ["RAW_DIR"])
OUTPUT_DIR = Path(os.environ["OUTPUT_DIR"])
REGEX_DIR  = Path(os.environ["REGEX_DIR"])

ENDPOINTS_FILE = RAW_DIR / "endpoints_raw.jsonl"
SECRETS_FILE   = RAW_DIR / "secrets.jsonl"
SINKS_FILE     = RAW_DIR / "dom_sinks.jsonl"
FINDINGS_FILE  = OUTPUT_DIR / "findings.json"

# ── Carrega patterns ──────────────────────────────────────────────────────────
def load(name: str) -> dict:
    with open(REGEX_DIR / name) as f:
        return json.load(f)

IDOR_PATTERNS   = load("idor_patterns.json")
BAC_PATTERNS    = load("bac_patterns.json")
SECRET_PATTERNS = load("secret_patterns.json")

MUTATING_METHODS = re.compile(
    r'\b(DELETE|PUT|PATCH)\b|'
    r'method\s*:\s*["\'](?:DELETE|PUT|PATCH)["\']|'
    r'type\s*:\s*["\'](?:DELETE|PUT|PATCH)["\']',
    re.IGNORECASE
)
# Endpoints REST reais sem ID — merecem ser MEDIUM (superfície de BAC/IDOR a verificar)
REST_API_PATH = re.compile(
    r'^/?(api|rest|v\d+|graphql)/\w',
    re.IGNORECASE
)
# Rotas de app com superfície BAC/IDOR mesmo sem padrão de ID explícito
SENSITIVE_ROUTE = re.compile(
    r"/(data-?export|file-?upload|order[s-]|payment|orders?"
    r"|forgot-?password|reset-?password|change-?password"
    r"|privacy|erasure|deluxe|wallet|score-?board"
    r"|admin|accounting|snippets)(/|$)",
    re.IGNORECASE
)


def score_endpoint(ep: dict, source_count: dict[str, int]) -> dict:
    """Calcula score e risco de um endpoint."""
    endpoint = ep.get("endpoint", "")
    source   = ep.get("source_js", "")
    score    = 0
    matches  = []

    # Hardcoded strings são re-scoreadas pelos padrões IDOR/BAC sobre o conteúdo da URL,
    # não pelo pattern_name genérico (que seria sempre INFO/score=1 independente do path)
    if ep.get("pattern_name") and ep.get("matched_by") != "hardcoded_string":
        base_score = 3 if ep.get("risk") == "HIGH" else 1
        score += base_score
        matches.append({
            "pattern": ep["pattern_name"],
            "risk": ep.get("risk"),
            "reason": ep.get("reason", "")
        })
    else:
        # Aplica todos os patterns sobre a string do endpoint (LinkFinder + hardcoded)
        for name, spec in {**IDOR_PATTERNS, **BAC_PATTERNS}.items():
            try:
                if re.search(spec["pattern"], endpoint, re.IGNORECASE):
                    base_score = 3 if spec["risk"] == "HIGH" else 1
                    score += base_score
                    matches.append({
                        "pattern": name,
                        "risk": spec["risk"],
                        "reason": spec["reason"]
                    })
            except re.error:
                pass

    # Bônus por método mutante identificado no contexto
    if MUTATING_METHODS.search(endpoint):
        score += 2
        matches.append({"pattern": "mutating_method", "risk": "HIGH",
                         "reason": "DELETE/PUT/PATCH method identified"})

    # Endpoints REST e rotas sensíveis sem ID ainda merecem MEDIUM
    path_part = urlparse(endpoint).path if endpoint.startswith("http") else endpoint
    if score == 0 and REST_API_PATH.match(path_part.lstrip("/")):
        score += 1
        matches.append({"pattern": "rest_api_surface", "risk": "MEDIUM",
                         "reason": "REST/API endpoint — verificar autenticação e autorização"})
    elif score == 0 and SENSITIVE_ROUTE.search(path_part):
        score += 1
        matches.append({"pattern": "sensitive_route", "risk": "MEDIUM",
                         "reason": "Rota sensível — export/upload/payment/admin merecem verificação de authz"})

    # Bônus por aparecer em múltiplos JS files
    if source_count.get(endpoint, 0) >= 2:
        score += 1

    # Risk tier
    if score >= 5:
        risk = "CRITICAL"
    elif score >= 3:
        risk = "HIGH"
    elif score >= 1:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        **ep,
        "score": score,
        "risk": risk,
        "matches": matches,
        "minified": ep.get("minified", False),
        "source_count": source_count.get(endpoint, 1)
    }


def classify_secret(raw: dict) -> dict:
    """Classifica findings do trufflehog com risk tier."""
    detector = raw.get("DetectorName", raw.get("detector_name", "unknown"))
    verified = raw.get("Verified", raw.get("verified", False))

    # Secrets verificados são sempre CRITICAL
    if verified:
        risk = "CRITICAL"
    elif detector.upper() in ("AWS", "STRIPE", "GITHUB", "PRIVATEKEY"):
        risk = "CRITICAL"
    else:
        risk = "HIGH"

    return {
        "type": "secret",
        "detector": detector,
        "verified": verified,
        "risk": risk,
        "source_js": raw.get("source_js", ""),
        "raw": raw
    }


def main():
    # ── Carrega endpoints ─────────────────────────────────────────────────────
    endpoints_raw = []
    if ENDPOINTS_FILE.exists():
        for line in ENDPOINTS_FILE.read_text().splitlines():
            try:
                endpoints_raw.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # Conta quantos JS files referenciam cada endpoint
    source_count: dict[str, int] = defaultdict(int)
    for ep in endpoints_raw:
        source_count[ep.get("endpoint", "")] += 1

    # Dedup por endpoint URL antes de classificar
    seen = set()
    unique_endpoints = []
    for ep in endpoints_raw:
        key = ep.get("endpoint", "")
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)

    print(f"  [classify] Endpoints únicos para classificar: {len(unique_endpoints)}")

    scored = [score_endpoint(ep, source_count) for ep in unique_endpoints]
    scored.sort(key=lambda x: (-x["score"], x["endpoint"]))

    # ── Carrega secrets ───────────────────────────────────────────────────────
    secrets = []
    if SECRETS_FILE.exists():
        for line in SECRETS_FILE.read_text().splitlines():
            try:
                secrets.append(classify_secret(json.loads(line)))
            except json.JSONDecodeError:
                pass

    # ── Carrega DOM sinks ─────────────────────────────────────────────────────
    dom_sinks = []
    if SINKS_FILE.exists():
        for line in SINKS_FILE.read_text().splitlines():
            try:
                dom_sinks.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # ── Monta output estruturado ──────────────────────────────────────────────
    findings = {
        "meta": {
            "target": os.environ.get("TARGET", ""),
            "program": os.environ.get("PROGRAM", ""),
            "mode": os.environ.get("MODE", ""),
            "total_endpoints": len(scored),
            "total_secrets": len(secrets),
            "total_dom_sinks": len(dom_sinks)
        },
        "endpoints": {
            "critical": [e for e in scored if e["risk"] == "CRITICAL"],
            "high":     [e for e in scored if e["risk"] == "HIGH"],
            "medium":   [e for e in scored if e["risk"] == "MEDIUM"],
            "low":      [e for e in scored if e["risk"] == "LOW"]
        },
        "secrets": secrets,
        "dom_sinks": dom_sinks
    }

    FINDINGS_FILE.write_text(json.dumps(findings, indent=2))

    # Sumário
    ep = findings["endpoints"]
    print(f"  [classify] CRITICAL: {len(ep['critical'])} | HIGH: {len(ep['high'])} | "
          f"MEDIUM: {len(ep['medium'])} | LOW: {len(ep['low'])}")
    print(f"  [classify] Secrets: {len(secrets)} | DOM Sinks: {len(dom_sinks)}")


if __name__ == "__main__":
    main()
