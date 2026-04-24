#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# 00_discover.sh — Fase 0: enumeração de subdomínios
# Só roda quando --enumerate-subs + --program com scope wildcard.
# =============================================================================

OUTFILE="$RAW_DIR/discovered_subs.txt"
LIVE_FILE="$RAW_DIR/live_subs.txt"

log() { echo -e "\033[0;36m  [discover]\033[0m $*"; }

# Extrai domínios wildcard do scope.yml
WILDCARD_DOMAINS=$(python3 - <<'EOF'
import yaml, sys, os
with open(os.environ['SCOPE_FILE']) as f:
    scope = yaml.safe_load(f)
domains = scope.get('in_scope', {}).get('domains', [])
for d in domains:
    if d.startswith('*.'):
        print(d[2:])  # remove o "*." — subfinder aceita o root
EOF
)

if [[ -z "$WILDCARD_DOMAINS" ]]; then
  log "Nenhum domínio wildcard no scope. Pulando enumeração."
  exit 0
fi

touch "$OUTFILE"

while IFS= read -r domain; do
  log "Enumerando subdomínios de: $domain"
  subfinder -d "$domain" -silent 2>/dev/null >> "$OUTFILE" || true
done <<< "$WILDCARD_DOMAINS"

# Remove duplicatas
sort -u "$OUTFILE" -o "$OUTFILE"
TOTAL=$(wc -l < "$OUTFILE")
log "Subdomínios encontrados: $TOTAL"

# Filtra só os vivos com httpx
log "Verificando hosts ativos (httpx)..."
httpx -l "$OUTFILE" -silent -o "$LIVE_FILE" 2>/dev/null || true

LIVE=$(wc -l < "$LIVE_FILE")
log "Hosts ativos: $LIVE"

# Valida cada host descoberto contra o scope antes de usar
python3 - <<'EOF'
import yaml, os, sys
sys.path.insert(0, '/app/scripts')
from scope_guard import ScopeGuard

scope_file = os.environ['SCOPE_FILE']
live_file  = os.environ.get('LIVE_FILE', '')

guard = ScopeGuard(scope_file)

with open(live_file) as f:
    hosts = [l.strip() for l in f if l.strip()]

allowed = []
for host in hosts:
    in_scope, reason = guard.check(host)
    if in_scope:
        allowed.append(host)

# Sobrescreve com só os in-scope
with open(live_file, 'w') as f:
    f.write('\n'.join(allowed))

print(f"  [discover] Hosts in-scope após validação: {len(allowed)}")
EOF

export LIVE_FILE
