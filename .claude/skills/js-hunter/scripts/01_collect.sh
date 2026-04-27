#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# 01_collect.sh — Fase 1: coleta de JS URLs
# Fontes: katana (ativo), gau + waybackurls (passivos).
# Scope guard é aplicado antes de qualquer requisição ativa.
# =============================================================================

log() { echo -e "\033[0;36m  [collect]\033[0m $*"; }

JS_RAW="$RAW_DIR/js_urls_raw.txt"
JS_FINAL="$RAW_DIR/js_urls.txt"
TARGETS_FILE="$RAW_DIR/collect_targets.txt"

# ── Monta lista de targets ────────────────────────────────────────────────────
# Prioridade: subdomínios descobertos na fase 0 > target único > domínios do scope
if [[ -f "$RAW_DIR/live_subs.txt" && -s "$RAW_DIR/live_subs.txt" ]]; then
  cp "$RAW_DIR/live_subs.txt" "$TARGETS_FILE"
  log "Usando $(wc -l < "$TARGETS_FILE") hosts da fase DISCOVER."
elif [[ -n "${TARGET:-}" ]]; then
  echo "$TARGET" > "$TARGETS_FILE"
  log "Target: $TARGET"
elif [[ -n "${SCOPE_FILE:-}" ]]; then
  python3 - <<'EOF'
import yaml, os
with open(os.environ['SCOPE_FILE']) as f:
    scope = yaml.safe_load(f)
domains = scope.get('in_scope', {}).get('domains', [])
for d in domains:
    # Wildcard vira o root para crawling (katana vai seguir subs via links)
    print(d.lstrip('*.'))
EOF
  > "$TARGETS_FILE"
  log "Targets do scope.yml: $(wc -l < "$TARGETS_FILE")"
fi

touch "$JS_RAW"

# ── Monta flags de autenticação ───────────────────────────────────────────────
AUTH_FLAGS=()
[[ -n "${COOKIE:-}" ]]      && AUTH_FLAGS+=(-H "Cookie: ${COOKIE}")
[[ -n "${AUTH_HEADER:-}" ]] && AUTH_FLAGS+=(-H "${AUTH_HEADER}")

# ── Modo passive: só fontes históricas, não toca o alvo ──────────────────────
if [[ "$MODE" == "passive" ]]; then
  log "Modo passive: gau + waybackurls (sem requisições ao alvo)"
  while IFS= read -r t; do
    domain="${t#*://}"   # remove scheme se presente
    log "  gau: $domain"
    gau --subs "$domain" 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
    log "  waybackurls: $domain"
    echo "$domain" | waybackurls 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
  done < "$TARGETS_FILE"

# ── Modo moderate: katana depth 2 + fontes passivas ──────────────────────────
elif [[ "$MODE" == "moderate" ]]; then
  log "Modo moderate: katana depth=2 rate=10 + gau + waybackurls"
  while IFS= read -r t; do
    domain="${t#*://}"
    target_url="http://$domain"
    [[ "$t" == http* ]] && target_url="$t"

    log "  katana: $target_url"
    katana \
      -u "$target_url" \
      -d 2 \
      -jc \
      -rl 10 \
      -silent \
      -o /tmp/katana_tmp.txt \
      "${AUTH_FLAGS[@]+"${AUTH_FLAGS[@]}"}" \
      2>/dev/null || true
    grep -iE '\.js(\?|$)' /tmp/katana_tmp.txt >> "$JS_RAW" 2>/dev/null || true

    gau --subs "$domain" 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
    echo "$domain" | waybackurls 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
  done < "$TARGETS_FILE"

# ── Modo aggressive: katana depth 5 + headless + fontes passivas ─────────────
elif [[ "$MODE" == "aggressive" ]]; then
  log "Modo aggressive: katana depth=5 headless rate=50 + gau + waybackurls"
  while IFS= read -r t; do
    domain="${t#*://}"
    target_url="http://$domain"
    [[ "$t" == http* ]] && target_url="$t"

    log "  katana (headless): $target_url"
    katana \
      -u "$target_url" \
      -d 5 \
      -jc \
      -rl 50 \
      -headless \
      -system-chrome \
      -silent \
      -o /tmp/katana_tmp.txt \
      "${AUTH_FLAGS[@]+"${AUTH_FLAGS[@]}"}" \
      2>/dev/null || true
    grep -iE '\.js(\?|$)' /tmp/katana_tmp.txt >> "$JS_RAW" 2>/dev/null || true

    gau --subs "$domain" 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
    echo "$domain" | waybackurls 2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_RAW" || true
  done < "$TARGETS_FILE"
fi

# ── Dedup + scope guard ───────────────────────────────────────────────────────
sort -u "$JS_RAW" -o "$JS_RAW"
BEFORE=$(wc -l < "$JS_RAW")
log "URLs coletadas (pré-filtro): $BEFORE"

python3 - <<'PYEOF'
import os, sys
sys.path.insert(0, '/app/scripts')

no_scope_check = os.environ.get('NO_SCOPE_CHECK', 'false').lower() == 'true'
scope_file     = os.environ.get('SCOPE_FILE', '')
raw_file       = os.environ['RAW_DIR'] + '/js_urls_raw.txt'
final_file     = os.environ['RAW_DIR'] + '/js_urls.txt'

with open(raw_file) as f:
    urls = [l.strip() for l in f if l.strip()]

if no_scope_check:
    with open(final_file, 'w') as f:
        f.write('\n'.join(urls))
    print(f"  [collect] {len(urls)} JS URLs (scope check desativado)")
else:
    from scope_guard import ScopeGuard
    guard = ScopeGuard(scope_file)
    allowed, rejected = [], []
    for url in urls:
        ok, reason = guard.check(url)
        (allowed if ok else rejected).append(url)

    with open(final_file, 'w') as f:
        f.write('\n'.join(allowed))
    with open(os.environ['RAW_DIR'] + '/js_urls_oos.txt', 'w') as f:
        f.write('\n'.join(rejected))

    print(f"  [collect] In-scope: {len(allowed)} | Out-of-scope descartadas: {len(rejected)}")
PYEOF

log "Coleta finalizada. $(wc -l < "$JS_FINAL" 2>/dev/null || echo 0) JS URLs in-scope."
