#!/usr/bin/env python3
"""
02_extract.py — Fase 2: extração de endpoints, secrets e DOM sinks.

Para cada JS URL in-scope:
  - Baixa o conteúdo
  - Roda LinkFinder para endpoints
  - Roda trufflehog via subprocess para secrets
  - Aplica regex de DOM sinks
  - Separa referências out-of-scope (intel passivo, não verifica ativamente)
"""

from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, "/app/scripts")
from scope_guard import ScopeGuard

RAW_DIR      = Path(os.environ["RAW_DIR"])
REGEX_DIR    = Path(os.environ["REGEX_DIR"])
OUTPUT_DIR   = Path(os.environ["OUTPUT_DIR"])
NO_SCOPE     = os.environ.get("NO_SCOPE_CHECK", "false").lower() == "true"
SCOPE_FILE   = os.environ.get("SCOPE_FILE", "")
COOKIE       = os.environ.get("COOKIE", "")
AUTH_HEADER  = os.environ.get("AUTH_HEADER", "")

JS_URLS_FILE = RAW_DIR / "js_urls.txt"
ENDPOINTS_FILE = RAW_DIR / "endpoints_raw.jsonl"
SECRETS_FILE   = RAW_DIR / "secrets.jsonl"
OOS_REFS_FILE  = OUTPUT_DIR / "out_of_scope_refs.txt"

guard = ScopeGuard(SCOPE_FILE if not NO_SCOPE else None)

# ── Carrega patterns ──────────────────────────────────────────────────────────
def load_patterns(name: str) -> dict:
    with open(REGEX_DIR / name) as f:
        return json.load(f)

IDOR_PATTERNS   = load_patterns("idor_patterns.json")
BAC_PATTERNS    = load_patterns("bac_patterns.json")
SECRET_PATTERNS = load_patterns("secret_patterns.json")
DOM_SINKS       = load_patterns("dom_sinks.json")
THIRD_PARTY     = set(DOM_SINKS.get("third_party_excludes", []))


def is_third_party(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return any(tp in host for tp in THIRD_PARTY)


def fetch_js(url: str) -> str | None:
    """Baixa conteúdo de um JS file. Retorna None em caso de erro."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 js-hunter/1.0")
        if COOKIE:
            req.add_header("Cookie", COOKIE)
        if AUTH_HEADER:
            key, _, val = AUTH_HEADER.partition(": ")
            req.add_header(key, val)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def extract_endpoints_linkfinder(js_content: str, base_url: str) -> list[dict]:
    """Usa LinkFinder para extrair endpoints do conteúdo JS."""
    results = []
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as tmp:
        tmp.write(js_content)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            ["python3", "/opt/linkfinder/linkfinder.py", "-i", tmp_path, "-o", "cli"],
            capture_output=True, text=True, timeout=30
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Resolve URL relativa
            if not line.startswith("http"):
                line = urljoin(base_url, line)
            results.append({"endpoint": line, "source_js": base_url})
    except Exception:
        pass
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return results


def extract_endpoints_regex(js_content: str, base_url: str) -> list[dict]:
    """Extrai endpoints via regex dos padrões IDOR/BAC diretamente no conteúdo JS."""
    results = []
    all_patterns = {**IDOR_PATTERNS, **BAC_PATTERNS}

    for name, spec in all_patterns.items():
        try:
            matches = re.findall(spec["pattern"], js_content, re.IGNORECASE)
            for match in matches:
                results.append({
                    "endpoint": match,
                    "source_js": base_url,
                    "pattern_name": name,
                    "risk": spec["risk"],
                    "reason": spec["reason"],
                    "matched_by": "regex_direct"
                })
        except re.error:
            pass

    return results


def extract_dom_sinks(js_content: str, base_url: str) -> list[dict]:
    """Detecta uso de DOM sinks perigosos no conteúdo JS."""
    results = []
    all_sinks = []
    for category, sinks in DOM_SINKS.items():
        if category == "third_party_excludes":
            continue
        if isinstance(sinks, list):
            all_sinks.extend(sinks)

    lines = js_content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for sink in all_sinks:
            if sink in line:
                results.append({
                    "sink": sink,
                    "line": lineno,
                    "context": line.strip()[:200],
                    "source_js": base_url
                })
    return results


def run_trufflehog(js_content: str, base_url: str) -> list[dict]:
    """Roda trufflehog3 no conteúdo JS para detecção de secrets."""
    results = []
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as tmp:
        tmp.write(js_content)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            ["trufflehog", "filesystem", tmp_path, "--json", "--no-update"],
            capture_output=True, text=True, timeout=60
        )
        for line in proc.stdout.splitlines():
            try:
                finding = json.loads(line)
                finding["source_js"] = base_url
                results.append(finding)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return results


def process_js_url(url: str) -> dict:
    """Processa uma JS URL e retorna todos os findings."""
    result = {
        "url": url,
        "third_party": is_third_party(url),
        "endpoints": [],
        "dom_sinks": [],
        "secrets": [],
        "oos_refs": [],
        "error": None
    }

    if result["third_party"]:
        return result

    content = fetch_js(url)
    if content is None:
        result["error"] = "fetch_failed"
        return result

    is_minified = any(len(line) > 500 for line in content.splitlines()[:10])
    result["minified"] = is_minified

    # Endpoints via LinkFinder
    lf_endpoints = extract_endpoints_linkfinder(content, url)
    # Endpoints via regex direta
    rx_endpoints = extract_endpoints_regex(content, url)

    # Separa in-scope vs out-of-scope refs
    all_endpoints = lf_endpoints + rx_endpoints
    for ep in all_endpoints:
        endpoint_url = ep.get("endpoint", "")
        if not endpoint_url.startswith("http"):
            result["endpoints"].append(ep)
            continue
        in_scope, _ = guard.check(endpoint_url)
        if in_scope or NO_SCOPE:
            result["endpoints"].append(ep)
        else:
            result["oos_refs"].append(endpoint_url)

    result["dom_sinks"] = extract_dom_sinks(content, url)
    result["secrets"]   = run_trufflehog(content, url)

    return result


def main():
    if not JS_URLS_FILE.exists():
        print("  [extract] Nenhuma JS URL encontrada. Abortando.")
        sys.exit(0)

    urls = [l.strip() for l in JS_URLS_FILE.read_text().splitlines() if l.strip()]
    print(f"  [extract] Processando {len(urls)} JS files...")

    all_endpoints = []
    all_secrets   = []
    all_oos_refs  = set()
    all_sinks     = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_js_url, url): url for url in urls}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            url = futures[future]
            if done % 10 == 0 or done == len(urls):
                print(f"  [extract] {done}/{len(urls)} processados...")

            all_endpoints.extend(result["endpoints"])
            all_secrets.extend(result["secrets"])
            all_oos_refs.update(result["oos_refs"])
            all_sinks.extend(result["dom_sinks"])

    # Dedup de endpoints por URL
    seen = set()
    deduped = []
    for ep in all_endpoints:
        key = ep.get("endpoint", "")
        if key not in seen:
            seen.add(key)
            deduped.append(ep)

    # Escreve outputs
    with open(ENDPOINTS_FILE, "w") as f:
        for ep in deduped:
            f.write(json.dumps(ep) + "\n")

    with open(SECRETS_FILE, "w") as f:
        for s in all_secrets:
            f.write(json.dumps(s) + "\n")

    with open(RAW_DIR / "dom_sinks.jsonl", "w") as f:
        for s in all_sinks:
            f.write(json.dumps(s) + "\n")

    with open(OOS_REFS_FILE, "w") as f:
        for ref in sorted(all_oos_refs):
            f.write(ref + "\n")

    print(f"  [extract] Endpoints extraídos: {len(deduped)}")
    print(f"  [extract] Secrets encontrados: {len(all_secrets)}")
    print(f"  [extract] DOM sinks detectados: {len(all_sinks)}")
    print(f"  [extract] Refs out-of-scope (intel passivo): {len(all_oos_refs)}")


if __name__ == "__main__":
    main()
