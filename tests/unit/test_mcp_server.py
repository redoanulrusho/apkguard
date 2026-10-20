"""MCP server: tool functions, the MCP protocol layer and the stdio entry point."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
import yaml

pytest.importorskip("mcp")  # optional extra: pip install ".[mcp]" or ".[dev]"

from mcp import Client, StdioServerParameters
from mcp.server.mcpserver.exceptions import ToolError

from apkguard import __version__
from apkguard.cli import mcp_main
from apkguard.config import parse_config
from apkguard.guidance import TRIAGE
from apkguard.mcp_server import build_server, explain_finding, list_rules, scan_apk
from apkguard.rules import ALL_RULES, RULES_BY_ID

FIXTURES = Path(__file__).parent.parent / "fixtures" / "apks"
NOTES = FIXTURES / "org.billthefarmer.notes_141.apk"


# --- tool functions ------------------------------------------------------------------------


@pytest.mark.integration
def test_scan_apk_returns_structured_findings() -> None:
    report = scan_apk(str(NOTES), min_severity="info")
    assert report.package == "org.billthefarmer.notes"
    assert report.counts_by_severity["high"] == 1
    assert report.total_matching == len(report.findings) == sum(report.counts_by_severity.values())
    first = report.findings[0]
    assert (first.rule_id, first.severity) == ("AG-MAN-003", "high")  # most severe first
    assert first.library is None and len(first.fingerprint) == 32


@pytest.mark.integration
def test_scan_apk_filters_and_truncates() -> None:
    high_only = scan_apk(str(NOTES), min_severity="high")
    assert [f.severity for f in high_only.findings] == ["high"]
    truncated = scan_apk(str(NOTES), min_severity="info", max_findings=2)
    assert len(truncated.findings) == 2 and truncated.truncated
    assert truncated.total_matching > 2


@pytest.mark.integration
def test_scan_apk_applies_config_file(tmp_path: Path) -> None:
    config = tmp_path / "apkguard.yml"
    config.write_text("suppress:\n  - rule: AG-MAN-003\n    reason: test\n", encoding="utf-8")
    report = scan_apk(str(NOTES), config_path=str(config))
    assert report.suppressed_findings == 1
    assert all(f.rule_id != "AG-MAN-003" for f in report.findings)


def test_scan_apk_errors_are_tool_errors(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="APK not found"):
        scan_apk(str(tmp_path / "missing.apk"))
    not_an_apk = tmp_path / "fake.apk"
    not_an_apk.write_text("hello", encoding="utf-8")
    with pytest.raises(ToolError, match="not a valid APK"):
        scan_apk(str(not_an_apk))
    bad_config = tmp_path / "bad.yml"
    bad_config.write_text("bogus: 1\n", encoding="utf-8")
    with pytest.raises(ToolError, match="unknown config key"):
        scan_apk(str(NOTES), config_path=str(bad_config))


def test_list_rules() -> None:
    assert [r.id for r in list_rules().rules] == [r.meta.id for r in ALL_RULES]
    secrets = list_rules(category="secrets").rules
    assert [r.id for r in secrets] == ["AG-SEC-001"]
    assert secrets[0].cwe == "CWE-798"


def test_every_rule_has_triage_guidance() -> None:
    assert set(TRIAGE) == set(RULES_BY_ID)
    for rule_id, triage in TRIAGE.items():
        assert triage.verify and triage.usually_benign_when, rule_id


def test_explain_finding() -> None:
    explanation = explain_finding("ag-man-004", location="com.example.Exported")
    assert explanation.rule_id == "AG-MAN-004"
    assert explanation.remediation == RULES_BY_ID["AG-MAN-004"].meta.remediation
    assert "sync adapters" in explanation.usually_benign_when
    assert explanation.references


@pytest.mark.parametrize("location", [None, "Lcom/x/Y;->run", 'weird "quoted" \\ name'])
def test_suppression_snippet_is_a_valid_config(location: str | None) -> None:
    snippet = explain_finding("AG-CODE-006", location=location).suppression_yaml
    config = parse_config(yaml.safe_load(snippet), set(RULES_BY_ID))
    assert config.suppress[0].rule == "AG-CODE-006"
    assert config.suppress[0].location == location


def test_explain_unknown_rule() -> None:
    with pytest.raises(ToolError, match="Unknown rule 'AG-NOPE'"):
        explain_finding("AG-NOPE")


# --- MCP protocol (in-process client) ------------------------------------------------------


def _with_client(action: Any) -> Any:
    async def main() -> Any:
        async with Client(build_server()) as client:
            return await action(client)

    return anyio.run(main)


def test_tools_are_listed_with_schemas_and_read_only_hints() -> None:
    async def tools(client: Client) -> Any:
        return (await client.list_tools()).tools

    by_name = {t.name: t for t in _with_client(tools)}
    assert set(by_name) == {"scan_apk", "list_rules", "explain_finding"}
    scan = by_name["scan_apk"]
    assert scan.input_schema["required"] == ["apk_path"]
    assert scan.output_schema is not None and "findings" in scan.output_schema["properties"]
    for tool in by_name.values():
        assert tool.annotations is not None and tool.annotations.read_only_hint
        assert tool.description


@pytest.mark.integration
def test_scan_over_mcp_returns_structured_content() -> None:
    async def call(client: Client) -> Any:
        return await client.call_tool("scan_apk", {"apk_path": str(NOTES)})

    result = _with_client(call)
    assert not result.is_error
    assert result.structured_content["package"] == "org.billthefarmer.notes"
    assert result.structured_content["findings"][0]["rule_id"] == "AG-MAN-003"


def test_tool_errors_reach_the_client_as_error_results() -> None:
    async def call(client: Client) -> Any:
        return await client.call_tool("explain_finding", {"rule_id": "AG-NOPE"})

    result = _with_client(call)
    assert result.is_error
    assert "Unknown rule" in result.content[0].text


# --- stdio entry point ---------------------------------------------------------------------


@pytest.mark.integration
def test_stdio_server_end_to_end() -> None:
    """Launch the server as a subprocess, exactly as Claude Desktop / Claude Code do."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from apkguard.cli import mcp_main; raise SystemExit(mcp_main())"],
    )

    async def main() -> Any:
        async with Client(params) as client:
            return await client.call_tool("list_rules", {"category": "code"})

    result = anyio.run(main)
    assert not result.is_error
    assert len(result.structured_content["rules"]) == 9


def test_apkguard_mcp_entry_point_is_installed() -> None:
    assert shutil.which("apkguard-mcp") or shutil.which(
        "apkguard-mcp", path=str(Path(sys.executable).parent)
    )


def test_mcp_main_without_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "apkguard.mcp_server", None)  # makes the import fail
    assert mcp_main() == 2
    hint = f'pip install "apkguard[mcp] @ git+https://github.com/redoanulrusho/apkguard@v{__version__}"'
    assert hint in capsys.readouterr().err
