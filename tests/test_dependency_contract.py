from importlib.metadata import version
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]


def _requirements(path: str) -> dict[str, Requirement]:
    return {
        requirement.name: requirement
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith(("#", "-r"))
        for requirement in [Requirement(line)]
    }


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-dev.txt", "backend/requirements.txt"])
def test_dependencies_have_lower_and_upper_bounds(path):
    for name, requirement in _requirements(path).items():
        operators = {specifier.operator for specifier in requirement.specifier}
        assert ">=" in operators, name
        assert "<" in operators, name


def test_shared_runtime_dependencies_use_matching_bounds():
    root = _requirements("requirements.txt")
    backend = _requirements("backend/requirements.txt")
    for name in root.keys() & backend.keys():
        assert root[name] == backend[name]
    assert version("pysnmp") in root["pysnmp"].specifier
    assert "4.4.12" not in root["pysnmp"].specifier
    assert "6.2.0" not in root["pysnmp"].specifier
