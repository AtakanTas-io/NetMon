from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pyinstaller_spec_includes_dynamic_application_and_report_modules():
    spec = (ROOT / "backend" / "NetMon.spec").read_text(encoding="utf-8")

    for module in ("application", "core.operations", "routers.operations", "openpyxl", "reportlab"):
        assert f"'{module}'" in spec


def test_release_workflow_builds_and_hashes_windows_executable():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert 'tags:\n      - "v*"' in workflow
    assert "pyinstaller --clean NetMon.spec" in workflow
    assert "Get-FileHash backend/dist/NetMon.exe -Algorithm SHA256" in workflow
    assert "gh release create" in workflow
