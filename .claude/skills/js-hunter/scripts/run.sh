#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# run.sh — Entry point do container js-hunter
# Parseia flags, valida pré-condições, orquestra as fases.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGEX_DIR="/app/regex"
TEMPLATES_DIR="/app/templates"
TARGETS_DIR="/targets"
OUTPUT_BASE="/output"

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""
PROGRAM=""
MODE="${MODE:-moderate}"
ENUMERATE_SUBS="${ENUMERATE_SUBS:-false}"
NO_SCOPE_CHECK="${NO_SCOPE_CHECK:-false}"
COOKIE="${COOKIE:-}"
AUTH_HEADER="${AUTH_HEADER:-}"

# ── Cores para output legível ─────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[js-hunter]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }

# ── Parse de argumentos ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)          TARGET="$2"; shift 2 ;;
    --program)         PROGRAM="$2"; shift 2 ;;
    --mode)            MODE="$2"; shift 2 ;;
    --enumerate-subs)  ENUMERATE_SUBS="true"; shift ;;
    --no-scope-check)  NO_SCOPE_CHECK="true"; shift ;;
    --cookie)          COOKIE="$2"; shift 2 ;;
    --header)          AUTH_HEADER="$2"; shift 2 ;;
    *) err "Flag desconhecida: $1" ;;
  esac
done

# ── Validações ────────────────────────────────────────────────────────────────
[[ -z "$TARGET" && -z "$PROGRAM" ]] && \
  err "Informe --target <domínio> ou --program <nome>."

[[ "$MODE" =~ ^(passive|moderate|aggressive)$ ]] || \
  err "Mode inválido: '$MODE'. Use passive, moderate ou aggressive."

if [[ -n "$PROGRAM" ]]; then
  SCOPE_FILE="$TARGETS_DIR/programs/$PROGRAM/scope.yml"
  [[ -f "$SCOPE_FILE" ]] || err "Scope file não encontrado: $SCOPE_FILE"
  log "Programa: $PROGRAM | Scope: $SCOPE_FILE"
fi

if [[ "$NO_SCOPE_CHECK" == "true" ]]; then
  warn "⚠  --no-scope-check ativado. Use APENAS em ambientes de lab autorizados."
fi

# ── Diretório de output ───────────────────────────────────────────────────────
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
RUN_ID="${PROGRAM:-$TARGET}"
RUN_ID="${RUN_ID//[^a-zA-Z0-9._-]/_}"
OUTPUT_DIR="$OUTPUT_BASE/$RUN_ID/$TIMESTAMP"
RAW_DIR="$OUTPUT_DIR/raw"
mkdir -p "$RAW_DIR"

log "Output: $OUTPUT_DIR"
log "Modo: $MODE"
echo ""

# ── Exporta variáveis para os sub-scripts ─────────────────────────────────────
export TARGET PROGRAM MODE ENUMERATE_SUBS NO_SCOPE_CHECK
export COOKIE AUTH_HEADER
export SCOPE_FILE OUTPUT_DIR RAW_DIR REGEX_DIR TEMPLATES_DIR
export SCRIPT_DIR

# ── Pipeline ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD} js-hunter | $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo ""

# Fase 0: Descoberta de subdomínios (só se wildcard scope + flag ativa)
if [[ "$ENUMERATE_SUBS" == "true" && -n "$PROGRAM" ]]; then
  log "Fase 0: DISCOVER — enumeração de subdomínios"
  bash "$SCRIPT_DIR/00_discover.sh"
else
  log "Fase 0: DISCOVER — skipped"
fi

# Fase 1: Coleta de JS URLs
log "Fase 1: COLLECT"
bash "$SCRIPT_DIR/01_collect.sh"

# Fase 2: Extração de endpoints e secrets
log "Fase 2: EXTRACT"
python3 "$SCRIPT_DIR/02_extract.py"

# Fase 3: Classificação por risco IDOR/BAC
log "Fase 3: CLASSIFY"
python3 "$SCRIPT_DIR/03_classify.py"

# Fase 4: Geração de relatórios
log "Fase 4: REPORT"
python3 "$SCRIPT_DIR/04_report.py"

# ── Sumário final ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
ok "Pipeline concluída."
echo -e "  report.md     → $OUTPUT_DIR/report.md"
echo -e "  findings.json → $OUTPUT_DIR/findings.json"
echo -e "  burp_import   → $OUTPUT_DIR/burp_import.txt"
echo -e "  out-of-scope  → $OUTPUT_DIR/out_of_scope_refs.txt"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
