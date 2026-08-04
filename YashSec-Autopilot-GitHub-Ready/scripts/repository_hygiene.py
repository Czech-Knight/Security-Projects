from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {'.git', '.venv', 'venv', '__pycache__', '.pytest_cache', 'node_modules', 'target', 'dist', 'build'}
PROHIBITED_NAMES = {'.env', 'yashsec.db', 'history delete.txt'}
PROHIBITED_SUFFIXES = {'.pem', '.p12', '.pfx', '.sqlite', '.sqlite3', '.log', '.pyc'}
MAX_FILE_BYTES = 25 * 1024 * 1024
TEXT_SUFFIXES = {'.py', '.js', '.html', '.css', '.md', '.txt', '.toml', '.yaml', '.yml', '.json', '.ps1', '.bat', '.ini', '.cfg', '.example', '.cff'}

patterns = {
    'private key header': re.compile('-----BEGIN ' + r'(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'AWS access key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    'GitHub token': re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b'),
    'GitHub fine-grained token': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b'),
    'Slack token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'personal Windows home path': re.compile(r'(?i)[A-Z]:\\Users\\(?!<|example|user)[^\\\s]+'),
    'personal Unix home path': re.compile(r'/(?:Users|home)/(?!<|example|user|runner|app|root)[^/\s]+'),
}


def iter_files():
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        yield path


def main() -> int:
    problems: list[str] = []
    for path in iter_files():
        rel = path.relative_to(ROOT)
        if path.name in PROHIBITED_NAMES or (path.name.startswith('.env.') and path.name != '.env.example'):
            problems.append(f'prohibited file: {rel}')
        if path.suffix.lower() in PROHIBITED_SUFFIXES:
            problems.append(f'prohibited file type: {rel}')
        if path.stat().st_size > MAX_FILE_BYTES:
            problems.append(f'oversized file ({path.stat().st_size} bytes): {rel}')
        if path == Path(__file__).resolve() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        for name, pattern in patterns.items():
            if pattern.search(text):
                problems.append(f'{name}: {rel}')
    if problems:
        print('Repository hygiene FAILED:')
        for item in sorted(set(problems)):
            print(f' - {item}')
        return 1
    print('Repository hygiene passed: no prohibited local artifacts or high-confidence credential formats found.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
