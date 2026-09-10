import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_pyinstaller_spec_includes_dynamic_application_and_report_modules():
    spec = (ROOT / "backend" / "NetMon.spec").read_text(encoding="utf-8")

    for module in (
        "application",
        "core.assurance",
        "core.operations",
        "core.search_engine",
        "routers.assurance",
        "routers.operations",
        "routers.search",
        "openpyxl",
        "reportlab",
    ):
        assert f"'{module}'" in spec


def test_release_workflow_builds_and_hashes_windows_executable():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert 'tags:\n      - "v*"' in workflow
    assert "python -m PyInstaller --clean --noconfirm NetMon.spec" in workflow
    assert "Get-FileHash backend/dist/NetMon.exe -Algorithm SHA256" in workflow
    assert "gh release create" in workflow


def test_source_package_excludes_runtime_files_and_preserves_existing_zip(tmp_path):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("Kaynak paket testi PowerShell gerektirir.")
    project = tmp_path / "project"
    script = project / "scripts/windows/package_release.ps1"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/windows/package_release.ps1", script)
    included = [
        "backend/app.py",
        "frontend/index.html",
        "tests/test_app.py",
        "docs/guide.md",
        "scripts/windows/package_release.ps1",
        "README.md",
    ]
    excluded = [
        "backend/.buildenv/python.exe",
        "backend/pytest_temp_final/trace.txt",
        "backend/netmon.db",
        "backend/netmon.db-wal",
        "backend/netmon.db-shm",
        "backend/.git/config",
        "tests/.coverage",
        "tests/.coverage.extra",
        "backend/__pycache__/module.pyc",
        "backend/build/module.py",
        "frontend/dist/bundle.js",
        "backend/.env",
        "backend/secret.key",
        "backend/venv/module.py",
        ".git/config",
        "unrelated/private.txt",
    ]
    for name in included + excluded:
        if name == "scripts/windows/package_release.ps1":
            continue
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture", encoding="utf-8")
    archive = tmp_path / "source.zip"
    command = [shell, "-NoProfile", "-File", str(script), "-OutputPath", str(archive)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    with zipfile.ZipFile(archive) as package:
        assert sorted(package.namelist()) == sorted(included)
        assert package.read("backend/app.py") == b"fixture"
    original = archive.read_bytes()
    repeated = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert repeated.returncode != 0
    assert archive.read_bytes() == original
