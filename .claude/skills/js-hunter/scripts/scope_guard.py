"""
scope_guard.py — Validador de scope para js-hunter.
Importado por todos os scripts Python da pipeline.
"""

from __future__ import annotations
import fnmatch
import re
from pathlib import Path
from urllib.parse import urlparse, unquote

try:
    import yaml
except ImportError:
    yaml = None  # fallback: no_scope_check mode

try:
    import tldextract
    def _extract_domain(url: str) -> str:
        ext = tldextract.extract(url)
        if ext.subdomain:
            return f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
        return f"{ext.domain}.{ext.suffix}"
except ImportError:
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname or url


class ScopeGuard:
    def __init__(self, scope_file: str | None):
        self.scope_file = scope_file
        self._scope: dict = {}
        self._no_check = not scope_file or not Path(scope_file).exists()

        if not self._no_check and yaml:
            with open(scope_file) as f:
                self._scope = yaml.safe_load(f) or {}

    def check(self, url: str) -> tuple[bool, str]:
        """Retorna (in_scope: bool, reason: str)."""
        if self._no_check:
            return True, "no_scope_check"

        domain = _extract_domain(url)
        path   = unquote(urlparse(url if "://" in url else f"http://{url}").path or "/")

        in_scope_domains  = self._scope.get("in_scope",  {}).get("domains", [])
        out_scope_domains = self._scope.get("out_of_scope", {}).get("domains", [])
        out_scope_paths   = self._scope.get("out_of_scope", {}).get("paths",  [])

        # 1. Verifica exclusões de path
        for excl_path in out_scope_paths:
            if fnmatch.fnmatch(path, excl_path):
                return False, f"path_excluded:{excl_path}"

        # 2. Verifica exclusões de domínio (precedência sobre inclusões)
        for excl in out_scope_domains:
            if self._domain_matches(domain, excl):
                return False, f"domain_excluded:{excl}"

        # 3. Verifica inclusões
        for pattern in in_scope_domains:
            if self._domain_matches(domain, pattern):
                return True, "in_scope"

        return False, "not_in_scope"

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """
        *.exemplo.com → cobre sub.exemplo.com, NÃO exemplo.com
        exemplo.com   → cobre só exemplo.com
        """
        domain  = domain.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")

        if pattern.startswith("*."):
            suffix = pattern[2:]
            return domain.endswith("." + suffix)

        return domain == pattern
