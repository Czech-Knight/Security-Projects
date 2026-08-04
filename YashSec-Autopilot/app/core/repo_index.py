from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from app.core.builtin_scanner import EXCLUDED_DIRS, MAX_FILE_SIZE, TEXT_EXTENSIONS


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_./:-]{2,}")
SENSITIVE_FILENAMES = {".env", ".env.local", ".env.production", ".env.development", "id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.json"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".keystore"}


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def _candidate_files(repo: Path):
    for path in repo.rglob("*"):
        relative_parts = path.relative_to(repo).parts
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        lowered = path.name.lower()
        if lowered in SENSITIVE_FILENAMES or path.suffix.lower() in SENSITIVE_SUFFIXES or lowered.startswith(".env"):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or lowered.startswith("readme"):
            yield path


def _chunks(text: str, max_chars: int = 3500, overlap: int = 300):
    if len(text) <= max_chars:
        yield 1, text
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        line_number = text.count("\n", 0, start) + 1
        yield line_number, text[start:end]
        if end == len(text):
            break
        start = max(start + 1, end - overlap)


def search_repository_context(repo_path: str | Path, query: str, limit: int = 6) -> list[dict[str, Any]]:
    repo = Path(repo_path).resolve()
    query_tokens = _tokens(query)
    if not query_tokens:
        return []
    scored: list[tuple[float, dict[str, Any]]] = []
    for path in _candidate_files(repo):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative = path.relative_to(repo).as_posix()
        path_tokens = _tokens(relative)
        for line_start, chunk in _chunks(text):
            chunk_tokens = _tokens(chunk)
            overlap = query_tokens & (chunk_tokens | path_tokens)
            if not overlap:
                continue
            density = len(overlap) / max(1, math.sqrt(len(chunk_tokens)))
            path_bonus = 0.4 * len(query_tokens & path_tokens)
            exact_bonus = 1.5 if query.lower() in chunk.lower() else 0
            score = density + path_bonus + exact_bonus
            scored.append(
                (
                    score,
                    {
                        "file_path": relative,
                        "line_start": line_start,
                        "content": chunk,
                        "score": round(score, 4),
                    },
                )
            )
    scored.sort(key=lambda item: item[0], reverse=True)
    return [payload for _, payload in scored[:limit]]
