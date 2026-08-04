from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class StartupCandidate:
    command: str
    label: str
    confidence: float
    source: str
    requires_confirmation: bool = True
    notes: str = ""


TEXT_FILE_LIMIT = 1_000_000
COMMON_PORTS = (3000, 4000, 5000, 5173, 8000, 8080, 8787)


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > TEXT_FILE_LIMIT:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _package_json(repo: Path, candidates: list[StartupCandidate], stacks: set[str]) -> None:
    path = repo / "package.json"
    if not path.exists():
        return
    stacks.add("Node.js")
    try:
        data = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return
    scripts = data.get("scripts") or {}
    preferred = ["dev", "start", "serve", "preview"]
    for index, script in enumerate(preferred):
        if script in scripts:
            confidence = 0.96 if script in {"dev", "start"} else 0.82
            candidates.append(
                StartupCandidate(
                    command=f"npm run {script}",
                    label=f"Node package script: {script}",
                    confidence=confidence - index * 0.02,
                    source="package.json",
                    notes=str(scripts[script])[:220],
                )
            )
    dependencies = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    for framework in ("react", "next", "vite", "express", "fastify", "nestjs"):
        if framework in dependencies or (framework == "nestjs" and any(k.startswith("@nestjs/") for k in dependencies)):
            stacks.add(framework.capitalize())


def _python(repo: Path, candidates: list[StartupCandidate], stacks: set[str]) -> None:
    requirements = "\n".join(
        _read_text(path).lower()
        for path in (repo / "requirements.txt", repo / "pyproject.toml", repo / "Pipfile")
        if path.exists()
    )
    if requirements or (repo / "setup.py").exists():
        stacks.add("Python")
    if (repo / "manage.py").exists():
        stacks.add("Django")
        candidates.append(
            StartupCandidate(
                command="python manage.py runserver 127.0.0.1:8000",
                label="Django development server",
                confidence=0.98,
                source="manage.py",
            )
        )
    if "fastapi" in requirements or "uvicorn" in requirements:
        stacks.add("FastAPI")
        app_candidates = []
        for file in list(repo.glob("*.py")) + list(repo.glob("app/*.py")) + list(repo.glob("src/*.py")):
            text = _read_text(file)
            if re.search(r"\b(FastAPI|APIRouter)\s*\(", text):
                module = file.relative_to(repo).with_suffix("").as_posix().replace("/", ".")
                variable = "app" if re.search(r"\bapp\s*=\s*FastAPI\s*\(", text) else "app"
                app_candidates.append(f"{module}:{variable}")
        module_target = app_candidates[0] if app_candidates else "main:app"
        candidates.append(
            StartupCandidate(
                command=f"python -m uvicorn {module_target} --host 127.0.0.1 --port 8000",
                label="FastAPI/Uvicorn server",
                confidence=0.88 if app_candidates else 0.65,
                source="Python dependency inspection",
                notes="Confirm the ASGI module if the application object is not named 'app'.",
            )
        )
    if "flask" in requirements:
        stacks.add("Flask")
        candidates.append(
            StartupCandidate(
                command="python -m flask run --host 127.0.0.1 --port 5000",
                label="Flask development server",
                confidence=0.78,
                source="Python dependency inspection",
                notes="FLASK_APP may need to be configured.",
            )
        )


def _containers(repo: Path, candidates: list[StartupCandidate], stacks: set[str]) -> None:
    compose_files = [repo / "docker-compose.yml", repo / "docker-compose.yaml", repo / "compose.yml", repo / "compose.yaml"]
    compose = next((p for p in compose_files if p.exists()), None)
    if compose:
        stacks.add("Docker Compose")
        candidates.append(
            StartupCandidate(
                command=f'docker compose -f "{compose.name}" up --build',
                label="Docker Compose application",
                confidence=0.94,
                source=compose.name,
                notes="Runs all services declared by the Compose file.",
            )
        )
    if (repo / "Dockerfile").exists():
        stacks.add("Docker")
        candidates.append(
            StartupCandidate(
                command="docker build -t yashsec-target . && docker run --rm -p 8080:8080 yashsec-target",
                label="Dockerfile (manual port confirmation recommended)",
                confidence=0.48,
                source="Dockerfile",
                notes="Edit the host/container port mapping before running if the image exposes another port.",
            )
        )


def _java_dotnet(repo: Path, candidates: list[StartupCandidate], stacks: set[str]) -> None:
    if (repo / "pom.xml").exists():
        stacks.update({"Java", "Maven"})
        candidates.append(StartupCandidate("mvn spring-boot:run", "Maven/Spring Boot", 0.82, "pom.xml"))
    if (repo / "gradlew").exists() or (repo / "gradlew.bat").exists():
        stacks.update({"Java", "Gradle"})
        command = ".\\gradlew.bat bootRun" if (repo / "gradlew.bat").exists() else "./gradlew bootRun"
        candidates.append(StartupCandidate(command, "Gradle/Spring Boot", 0.82, "gradlew"))
    solutions = list(repo.glob("*.sln"))
    projects = list(repo.glob("**/*.csproj"))[:5]
    if solutions or projects:
        stacks.add(".NET")
        target = solutions[0].name if solutions else projects[0].relative_to(repo).as_posix()
        candidates.append(StartupCandidate(f'dotnet run --project "{target}"', ".NET application", 0.72, target))


def _readme_commands(repo: Path, candidates: list[StartupCandidate]) -> None:
    readme = next((p for p in (repo / "README.md", repo / "README.txt", repo / "readme.md") if p.exists()), None)
    if not readme:
        return
    text = _read_text(readme)
    command_patterns = [
        r"(?im)^\s*(npm\s+(?:run\s+)?(?:dev|start|serve))\s*$",
        r"(?im)^\s*(pnpm\s+(?:run\s+)?(?:dev|start|serve))\s*$",
        r"(?im)^\s*(yarn\s+(?:dev|start|serve))\s*$",
        r"(?im)^\s*(python(?:3)?\s+-m\s+uvicorn\s+[^\r\n`]+)",
        r"(?im)^\s*(uvicorn\s+[^\r\n`]+)",
        r"(?im)^\s*(docker\s+compose\s+up[^\r\n`]*)",
        r"(?im)^\s*(dotnet\s+run[^\r\n`]*)",
    ]
    seen = {candidate.command.lower() for candidate in candidates}
    for pattern in command_patterns:
        for match in re.findall(pattern, text):
            command = match.strip().strip("`")
            if command.lower() not in seen and len(command) < 240:
                candidates.append(
                    StartupCandidate(command, "Command documented in README", 0.76, readme.name, notes="Review before execution.")
                )
                seen.add(command.lower())


def _detect_ports(repo: Path) -> list[int]:
    ports: set[int] = set()
    interesting_files = [
        repo / ".env",
        repo / ".env.example",
        repo / "package.json",
        repo / "docker-compose.yml",
        repo / "docker-compose.yaml",
        repo / "compose.yml",
        repo / "compose.yaml",
    ]
    interesting_files += list(repo.glob("*.py"))[:20] + list(repo.glob("src/*.*"))[:30] + list(repo.glob("app/*.*"))[:30]
    pattern = re.compile(r"(?i)(?:port\s*[=:]\s*|--port\s+|listen\s*\(\s*)(\d{2,5})")
    for path in interesting_files:
        if not path.exists() or not path.is_file():
            continue
        for value in pattern.findall(_read_text(path)):
            port = int(value)
            if 1 <= port <= 65535:
                ports.add(port)
    if not ports:
        ports.update(COMMON_PORTS)
    return sorted(ports)


def detect_repository(repo_path: str | Path) -> dict[str, Any]:
    repo = Path(repo_path).resolve()
    candidates: list[StartupCandidate] = []
    stacks: set[str] = set()
    _package_json(repo, candidates, stacks)
    _python(repo, candidates, stacks)
    _containers(repo, candidates, stacks)
    _java_dotnet(repo, candidates, stacks)
    _readme_commands(repo, candidates)

    unique: dict[str, StartupCandidate] = {}
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        unique.setdefault(candidate.command.lower(), candidate)

    return {
        "stacks": sorted(stacks),
        "startup_candidates": [asdict(item) for item in unique.values()],
        "port_hints": _detect_ports(repo),
        "recommended_command": next(iter(unique.values())).command if unique else None,
        "requires_user_input": not unique or next(iter(unique.values())).confidence < 0.85,
    }
