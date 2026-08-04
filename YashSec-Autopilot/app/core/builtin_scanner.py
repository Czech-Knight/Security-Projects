from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from app.core.normalizer import with_defaults


EXCLUDED_DIRS = {
    ".git", ".idea", ".vscode", "node_modules", "vendor", "dist", "build", "coverage",
    ".venv", "venv", "__pycache__", ".next", "target", "bin", "obj", "data",
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".php", ".rb", ".go",
    ".rs", ".kt", ".kts", ".sql", ".yaml", ".yml", ".json", ".toml", ".ini",
    ".properties", ".xml", ".env", ".sh", ".ps1", ".html", ".vue", ".svelte",
}
MAX_FILE_SIZE = 1_500_000


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    regex: re.Pattern[str]
    severity: str
    description: str
    remediation: str
    cwe: str | None = None
    owasp: str | None = None


RULES = (
    Rule(
        "dangerous-eval",
        "Dynamic code execution detected",
        re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
        "high",
        "Dynamic code execution can turn untrusted input into arbitrary code execution.",
        "Remove dynamic execution or enforce a strict allow-list and parse data instead of code.",
        "CWE-95",
        "A03:2021 Injection",
    ),
    Rule(
        "shell-command",
        "Potential command execution sink",
        re.compile(r"(?:child_process\.(?:exec|execSync)|os\.system|subprocess\.(?:run|Popen)\([^\n]*shell\s*=\s*True)", re.IGNORECASE),
        "high",
        "Shell execution becomes dangerous when any command fragment can be influenced by a user or external data.",
        "Use argument arrays, avoid shell=True, and validate values with strict allow-lists.",
        "CWE-78",
        "A03:2021 Injection",
    ),
    Rule(
        "sql-concatenation",
        "Possible SQL query construction with concatenation",
        re.compile(r"(?i)(?:select|insert|update|delete).{0,160}(?:\+|\.format\(|\$\{|f[\"'])"),
        "high",
        "Building SQL with string concatenation may allow SQL injection.",
        "Use parameterised queries or the ORM's bound-parameter API.",
        "CWE-89",
        "A03:2021 Injection",
    ),
    Rule(
        "sensitive-body-logging",
        "Potential sensitive request body logging",
        re.compile(r"(?i)(?:log(?:ger)?\.(?:info|debug|warn|error)|console\.log)\s*\([^\n]*(?:req(?:uest)?\.body|cv|resume|password|token)"),
        "high",
        "Full request bodies, CVs, tokens, or credentials can leak through application logs.",
        "Log a correlation ID, operation, status, and non-sensitive metadata only. Apply structured redaction.",
        "CWE-532",
        "A09:2021 Security Logging and Monitoring Failures",
    ),
    Rule(
        "weak-jwt-verification",
        "JWT signature verification may be disabled",
        re.compile(r"(?i)(?:verify_signature|verify)\s*[=:]\s*(?:false|False|0)"),
        "critical",
        "Disabling token verification can permit forged authentication tokens.",
        "Always verify the signature, issuer, audience, lifetime, and accepted algorithms.",
        "CWE-347",
        "A07:2021 Identification and Authentication Failures",
    ),
    Rule(
        "cors-wildcard-credentials",
        "Broad CORS policy detected",
        re.compile(r"(?is)(?:allow_origins|origin)\s*[=:]\s*\[?\s*[\"']\*[\"'].*?(?:credentials|allow_credentials)\s*[=:]\s*(?:true|True)"),
        "high",
        "Wildcard origins combined with credentials can expose authenticated responses to untrusted origins.",
        "Use an explicit origin allow-list and review whether credentials are required.",
        "CWE-942",
        "A05:2021 Security Misconfiguration",
    ),
    Rule(
        "debug-enabled",
        "Debug mode appears enabled",
        re.compile(r"(?i)\b(?:debug|DEBUG)\s*[=:]\s*(?:true|True|1)\b"),
        "medium",
        "Debug mode can expose stack traces, configuration, and internal application details.",
        "Disable debug mode outside a local development environment.",
        "CWE-489",
        "A05:2021 Security Misconfiguration",
    ),
    Rule(
        "hardcoded-password",
        "Possible hard-coded credential",
        re.compile(r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b\s*[=:]\s*[\"'][^\"'\n]{8,}[\"']"),
        "high",
        "A credential-like value appears to be embedded directly in source or configuration.",
        "Move the value to a local environment file or secret manager and rotate it if it was real.",
        "CWE-798",
        "A07:2021 Identification and Authentication Failures",
    ),
    Rule(
        "insecure-random",
        "Non-cryptographic random generator used near security-sensitive data",
        re.compile(r"(?i)(?:Math\.random\(\)|random\.random\(\)).{0,120}(?:token|password|secret|session|otp)"),
        "medium",
        "Predictable random values are unsuitable for tokens, reset links, or one-time codes.",
        "Use a cryptographically secure generator such as secrets.token_urlsafe or crypto.randomBytes.",
        "CWE-338",
        "A02:2021 Cryptographic Failures",
    ),
)


def iter_files(repo: Path) -> Iterator[Path]:
    for path in repo.rglob("*"):
        relative_parts = path.relative_to(repo).parts
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name.startswith(".env"):
            yield path


def _snippet(lines: list[str], line_number: int, radius: int = 2) -> str:
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    return "\n".join(f"{index + 1:>5} | {lines[index]}" for index in range(start, end))[:3000]


def scan(repo_path: str | Path) -> list[dict]:
    repo = Path(repo_path).resolve()
    findings: list[dict] = []
    for path in iter_files(repo):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        relative = path.relative_to(repo).as_posix()
        for rule in RULES:
            for match in rule.regex.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                findings.append(
                    with_defaults(
                        {
                            "title": rule.title,
                            "description": rule.description,
                            "severity": rule.severity,
                            "tool": "yashsec-builtin",
                            "category": rule.rule_id,
                            "cwe": rule.cwe,
                            "owasp": rule.owasp,
                            "file_path": relative,
                            "line_start": line_number,
                            "line_end": line_number,
                            "evidence": _snippet(lines, line_number),
                            "remediation": rule.remediation,
                            "raw": {"matched_text": match.group(0)[:160]},
                        }
                    )
                )
    return findings
