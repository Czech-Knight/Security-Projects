from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app.core import repo_service


def test_zip_path_traversal_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "repositories"
    workspace.mkdir()
    monkeypatch.setattr(repo_service, "REPOSITORY_DIR", workspace)
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../outside.txt", "not allowed")
    with pytest.raises(ValueError, match="(?i)unsafe.*path"):
        repo_service.extract_zip_repository(archive, "evil")
    assert not (tmp_path / "outside.txt").exists()


def test_safe_zip_extracts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "repositories"
    workspace.mkdir()
    monkeypatch.setattr(repo_service, "REPOSITORY_DIR", workspace)
    archive = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("project/package.json", '{"name":"safe"}')
        handle.writestr("project/src/app.js", "console.log('ok')")
    result = repo_service.extract_zip_repository(archive, "safe")
    assert (result / "package.json").exists()
    assert (result / "src" / "app.js").exists()
