from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize_text(value: Any) -> str | None:
    """Convert scanner metadata into a stable text value for SQLite/UI fields."""
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (list, tuple, set)):
        parts = [normalize_text(item) for item in value]
        cleaned = [part for part in parts if part]
        return ", ".join(cleaned) or None
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def normalize_evidence(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def normalize_severity(value: str | None, default: str = "medium") -> str:
    text = (value or default).strip().lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "unknown": default,
        "negligible": "info",
        "moderate": "medium",
        "important": "high",
    }
    text = mapping.get(text, text)
    return text if text in SEVERITY_ORDER else default


def fingerprint(finding: dict[str, Any]) -> str:
    canonical = "|".join(
        str(finding.get(key) or "").strip().lower()
        for key in ("tool", "title", "file_path", "line_start", "endpoint", "category", "cwe")
    )
    return hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()


def with_defaults(finding: dict[str, Any]) -> dict[str, Any]:
    references = finding.get("references") or []
    if not isinstance(references, list):
        references = [references]

    normalized = {
        "title": normalize_text(finding.get("title")) or "Security finding",
        "description": normalize_text(finding.get("description")) or "The scanner reported a potential security issue.",
        "severity": normalize_severity(normalize_text(finding.get("severity"))),
        "confidence": (normalize_text(finding.get("confidence")) or "medium").lower(),
        "tool": normalize_text(finding.get("tool")) or "unknown",
        "category": normalize_text(finding.get("category")),
        "cwe": normalize_text(finding.get("cwe")),
        "owasp": normalize_text(finding.get("owasp")),
        "file_path": normalize_text(finding.get("file_path")),
        "line_start": finding.get("line_start"),
        "line_end": finding.get("line_end"),
        "function_name": normalize_text(finding.get("function_name")),
        "endpoint": normalize_text(finding.get("endpoint")),
        "evidence": normalize_evidence(finding.get("evidence")),
        "remediation": normalize_text(finding.get("remediation")) or "Review the affected code and apply the scanner's recommended secure pattern.",
        "references": references,
        "raw": finding.get("raw") or {},
    }
    normalized["fingerprint"] = finding.get("fingerprint") or fingerprint(normalized)
    return normalized


def semgrep_findings(payload: dict[str, Any], repo: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = extra.get("severity") or metadata.get("impact") or "medium"
        path = item.get("path")
        try:
            path = str(Path(path).resolve().relative_to(repo.resolve())) if path else None
        except (ValueError, OSError):
            pass
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(v) for v in cwe)
        references = metadata.get("references") or []
        output.append(
            with_defaults(
                {
                    "title": extra.get("message") or item.get("check_id") or "Semgrep finding",
                    "description": extra.get("message") or "Semgrep matched an insecure code pattern.",
                    "severity": severity,
                    "tool": "semgrep",
                    "category": item.get("check_id"),
                    "cwe": cwe,
                    "owasp": metadata.get("owasp"),
                    "file_path": path,
                    "line_start": (item.get("start") or {}).get("line"),
                    "line_end": (item.get("end") or {}).get("line"),
                    "evidence": (extra.get("lines") or "")[:3000],
                    "remediation": metadata.get("fix") or extra.get("fix") or "Apply a secure alternative and add a regression test.",
                    "references": references if isinstance(references, list) else [references],
                    "raw": item,
                }
            )
        )
    return output


def gitleaks_findings(payload: list[dict[str, Any]], repo: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in payload:
        file_path = item.get("File") or item.get("file")
        if file_path:
            try:
                file_path = str(Path(file_path).resolve().relative_to(repo.resolve()))
            except (ValueError, OSError):
                pass
        secret = item.get("Secret") or item.get("secret") or ""
        redacted = f"{secret[:3]}…{secret[-2:]}" if len(secret) > 6 else "[redacted]"
        output.append(
            with_defaults(
                {
                    "title": item.get("Description") or item.get("RuleID") or "Potential hard-coded secret",
                    "description": "A value matching a known secret pattern was found in the repository.",
                    "severity": "high",
                    "tool": "gitleaks",
                    "category": item.get("RuleID") or item.get("rule_id"),
                    "cwe": "CWE-798",
                    "owasp": "A07:2021 Identification and Authentication Failures",
                    "file_path": file_path,
                    "line_start": item.get("StartLine") or item.get("start_line"),
                    "line_end": item.get("EndLine") or item.get("end_line"),
                    "evidence": f"Matched secret: {redacted}",
                    "remediation": "Revoke/rotate the value, remove it from source and history, and load it from a secret manager or environment variable.",
                    "raw": {k: ("[redacted]" if k.lower() == "secret" else v) for k, v in item.items()},
                }
            )
        )
    return output


def trivy_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for result in payload.get("Results", []):
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            installed = vuln.get("InstalledVersion")
            fixed = vuln.get("FixedVersion") or "No fixed version reported"
            output.append(
                with_defaults(
                    {
                        "title": f"{vuln.get('VulnerabilityID', 'Vulnerability')} in {vuln.get('PkgName', 'dependency')}",
                        "description": vuln.get("Title") or vuln.get("Description") or "A vulnerable dependency was detected.",
                        "severity": vuln.get("Severity"),
                        "tool": "trivy",
                        "category": "dependency-vulnerability",
                        "cwe": ", ".join(vuln.get("CweIDs") or []),
                        "owasp": "A06:2021 Vulnerable and Outdated Components",
                        "file_path": target,
                        "evidence": f"Installed: {installed}; fixed: {fixed}",
                        "remediation": f"Upgrade {vuln.get('PkgName', 'the package')} to {fixed} after compatibility testing.",
                        "references": vuln.get("References") or [],
                        "raw": vuln,
                    }
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            output.append(
                with_defaults(
                    {
                        "title": misconfig.get("Title") or misconfig.get("ID") or "Configuration finding",
                        "description": misconfig.get("Description") or "Trivy detected an insecure configuration.",
                        "severity": misconfig.get("Severity"),
                        "tool": "trivy",
                        "category": misconfig.get("Type") or "misconfiguration",
                        "file_path": target,
                        "line_start": ((misconfig.get("CauseMetadata") or {}).get("StartLine")),
                        "line_end": ((misconfig.get("CauseMetadata") or {}).get("EndLine")),
                        "evidence": ((misconfig.get("CauseMetadata") or {}).get("Code") or {}).get("Lines"),
                        "remediation": misconfig.get("Resolution") or "Apply a hardened configuration and retest.",
                        "references": misconfig.get("References") or [],
                        "raw": misconfig,
                    }
                )
            )
    return output


def parse_json_file(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return default
