# syntax=docker/dockerfile:1
# =============================================================================
# STAGE 1: Go tools builder
# Usa Debian Bookworm (mesma glibc do final) + GOTOOLCHAIN=auto para
# baixar Go >= 1.25.7 que katana exige, sem trocar a imagem base.
# =============================================================================
FROM --platform=linux/amd64 golang:1.22-bookworm AS go-builder

# GOTOOLCHAIN=auto: Go 1.22 baixa automaticamente a versão exigida pelo módulo
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates gcc \
    && rm -rf /var/lib/apt/lists/*

# katana usa go-tree-sitter (CGO obrigatório) — sem CGO_ENABLED=0
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
# demais tools não precisam de CGO — binários estáticos, sem dependência de libs
RUN CGO_ENABLED=0 go install github.com/lc/gau/v2/cmd/gau@latest
RUN CGO_ENABLED=0 go install github.com/tomnomnom/waybackurls@latest
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# =============================================================================
# STAGE 2: Python tools builder
# =============================================================================
FROM --platform=linux/amd64 python:3.12-slim AS py-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
    jsbeautifier \
    argparse \
    requests \
    jinja2 \
    pyyaml \
    tldextract \
    urllib3

RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder && \
    pip install --no-cache-dir -r /opt/linkfinder/requirements.txt

# =============================================================================
# STAGE 3: trufflehog builder
# Baixa binário pré-compilado — evita replace directives do go.mod
# =============================================================================
FROM --platform=linux/amd64 debian:bookworm-slim AS trufflehog-builder

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# =============================================================================
# STAGE 4: Imagem final
# python:3.12-slim = Debian Bookworm → mesma glibc do go-builder
# =============================================================================
FROM --platform=linux/amd64 python:3.12-slim AS final

LABEL maintainer="js-hunter" \
      description="JS recon pipeline for IDOR/BAC bug bounty hunting"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    libglib2.0-0 \
    libnss3 \
    libxss1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxrandr2 \
    libgbm1 \
    jq \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go/bin/katana      /usr/local/bin/katana
COPY --from=go-builder /go/bin/gau         /usr/local/bin/gau
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/waybackurls
COPY --from=go-builder /go/bin/subfinder   /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx       /usr/local/bin/httpx
COPY --from=trufflehog-builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog

COPY --from=py-builder /opt/venv       /opt/venv
COPY --from=py-builder /opt/linkfinder /opt/linkfinder

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CHROME_BIN=/usr/bin/chromium \
    CHROME_PATH=/usr/bin/chromium \
    KATANA_CHROME_ARGS="--no-sandbox --disable-setuid-sandbox --disable-dev-shm-usage"

COPY .claude/skills/js-hunter/scripts/  /app/scripts/
COPY .claude/skills/js-hunter/regex/    /app/regex/
COPY .claude/skills/js-hunter/templates/ /app/templates/

WORKDIR /app

RUN chmod +x /app/scripts/*.sh 2>/dev/null || true

VOLUME ["/output", "/targets"]

ENTRYPOINT ["/app/scripts/run.sh"]
