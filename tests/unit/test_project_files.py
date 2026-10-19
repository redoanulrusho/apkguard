"""Sanity checks for shipped, non-Python project files (example config, GitHub Action)."""

from __future__ import annotations

from pathlib import Path

import yaml

from apkguard.config import load_config
from apkguard.model import Severity
from apkguard.rules import RULES_BY_ID

ROOT = Path(__file__).resolve().parents[2]


def test_example_config_is_valid() -> None:
    cfg = load_config(ROOT / "examples" / ".apkguard.yml", set(RULES_BY_ID))
    assert cfg.fail_on is Severity.HIGH
    assert cfg.suppress, "example should demonstrate suppressions"


def test_action_definition() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["apk"]["required"] is True
    assert action["inputs"]["fail-on"]["default"] == "high"
    steps = action["runs"]["steps"]
    scan = next(s for s in steps if s.get("id") == "scan")
    # Untrusted inputs must reach the shell via env, never be interpolated into the script.
    assert "${{" not in scan["run"]
    # Every optional input reaches the CLI through an environment variable.
    for name, env in (("baseline", "BASELINE"), ("library-findings", "LIBRARY_FINDINGS")):
        assert action["inputs"][name]["default"] == ""
        assert scan["env"][env] == f"${{{{ inputs.{name} }}}}"
        assert f'"${env}"' in scan["run"]
    uses = [s["uses"] for s in steps if "uses" in s]
    assert any(u.startswith("github/codeql-action/upload-sarif@") for u in uses)


def test_workflows_are_valid_yaml() -> None:
    for path in [*(ROOT / ".github" / "workflows").glob("*.yml"), ROOT / "examples" /
                 "github-workflow.yml"]:  # fmt: skip
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "jobs" in data, path


def test_issue_forms_are_well_formed() -> None:
    forms = sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))
    assert len(forms) >= 3
    for path in forms:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if path.name == "config.yml":
            assert data["blank_issues_enabled"] is False
            continue
        assert data["name"] and data["description"], path
        ids = [item["id"] for item in data["body"] if "id" in item]
        assert len(ids) == len(set(ids)), f"duplicate ids in {path.name}"
        assert all(
            item["type"] in {"markdown", "input", "textarea", "dropdown"} for item in data["body"]
        )


def test_version_is_single_sourced() -> None:
    from apkguard import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
