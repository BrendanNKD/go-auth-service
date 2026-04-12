#!/usr/bin/env python3
"""Render SARIF scanner outputs into a single HTML security report."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "note": 4,
    "unknown": 5,
}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def severity_from_result(result: dict[str, Any], rule: dict[str, Any]) -> str:
    properties = rule.get("properties") or {}
    result_properties = result.get("properties") or {}

    for source in (result_properties, properties):
        raw = source.get("security-severity") or source.get("cvssScore")
        if raw is None:
            continue
        try:
            score = float(raw)
        except (TypeError, ValueError):
            continue
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"

    raw_severity = (
        properties.get("problem.severity")
        or result_properties.get("problem.severity")
        or result.get("level")
        or (rule.get("defaultConfiguration") or {}).get("level")
        or "unknown"
    )
    severity = str(raw_severity).lower()
    if severity in {"critical", "high", "medium", "low"}:
        return severity
    if severity == "error":
        return "high"
    if severity == "warning":
        return "medium"
    if severity in {"note", "none", "recommendation"}:
        return "note"
    return "unknown"


def message_text(message: dict[str, Any] | str | None) -> str:
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return ""
    return str(message.get("text") or message.get("markdown") or "")


def first_location(result: dict[str, Any]) -> str:
    locations = result.get("locations") or []
    if not locations:
        return "-"
    physical = (locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    uri = artifact.get("uri") or "-"
    line = region.get("startLine")
    if line:
        return f"{uri}:{line}"
    return str(uri)


def rule_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    tool = run.get("tool") or {}
    driver = tool.get("driver") or {}
    for component in [driver, *(tool.get("extensions") or [])]:
        for rule in component.get("rules") or []:
            rule_id = str(rule.get("id") or "")
            if rule_id:
                rules[rule_id] = rule
    return rules


def parse_sarif_file(path: Path, root: Path) -> list[dict[str, Any]]:
    data = read_json(path)
    if not data:
        return []

    findings: list[dict[str, Any]] = []
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name")) or "Unknown scanner"
        rules = rule_map(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
            rule = rules.get(rule_id, {})
            message = message_text(result.get("message")) or message_text(rule.get("shortDescription"))
            finding = {
                "tool": str(tool),
                "rule": rule_id,
                "severity": severity_from_result(result, rule),
                "message": message or "No message provided.",
                "location": first_location(result),
                "source": str(path.relative_to(root)),
            }
            findings.append(finding)
    return findings


def collect_findings(input_dir: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    root = input_dir.resolve()
    sarif_files = sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".sarif")
    findings: list[dict[str, Any]] = []
    for path in sarif_files:
        findings.extend(parse_sarif_file(path, root))
    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["tool"], item["rule"], item["location"]))
    return findings, sarif_files


def count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def render_finding_rows(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="6">No SARIF findings were parsed from the downloaded scan artifacts.</td></tr>'
    rows: list[str] = []
    for finding in findings[:500]:
        severity = finding["severity"]
        rows.append(
            "<tr>"
            f"<td><span class=\"pill severity-{esc(severity)}\">{esc(severity)}</span></td>"
            f"<td>{esc(finding['tool'])}</td>"
            f"<td>{esc(finding['rule'])}</td>"
            f"<td>{esc(finding['message'])}</td>"
            f"<td>{esc(finding['location'])}</td>"
            f"<td>{esc(finding['source'])}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_scanner_rows(findings: list[dict[str, Any]]) -> str:
    tool_counts = count_by(findings, "tool")
    if not tool_counts:
        return '<tr><td colspan="2">No scanner findings were parsed.</td></tr>'
    return "\n".join(f"<tr><td>{esc(tool)}</td><td>{count}</td></tr>" for tool, count in tool_counts.items())


def render_source_rows(sarif_files: list[Path], input_dir: Path) -> str:
    if not sarif_files:
        return '<tr><td>No SARIF files found.</td></tr>'
    root = input_dir.resolve()
    return "\n".join(f"<tr><td>{esc(path.relative_to(root))}</td></tr>" for path in sarif_files)


def render_html(findings: list[dict[str, Any]], sarif_files: list[Path], input_dir: Path, output_path: Path, title: str) -> None:
    counts = severity_counts(findings)
    generated_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(findings)
    top_status = "Needs Review" if total else "No Findings"
    top_class = "severity-high" if total else "severity-low"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --ink: #101820;
      --muted: #60707f;
      --line: #dce3ea;
      --critical: #8f1d1d;
      --high: #c43d3d;
      --medium: #b7791f;
      --low: #1f8f5f;
      --note: #4267b2;
      --unknown: #64748b;
      --shadow: 0 18px 42px rgba(16, 24, 32, 0.10);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: linear-gradient(135deg, #f5f7fb 0%, #edf7f2 50%, #f9eef1 100%);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ width: min(1240px, calc(100% - 32px)); margin: 0 auto; padding: 34px 0 48px; }}
    header, .panel, table {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 20px;
      align-items: end;
      padding: 28px;
    }}
    h1 {{ margin: 0; font-size: 32px; letter-spacing: 0; }}
    h2 {{ margin: 34px 0 14px; font-size: 20px; letter-spacing: 0; }}
    p {{ margin: 6px 0 0; color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }}
    .metric {{ padding: 18px; }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 800; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 30px; line-height: 1.1; }}
    .pill {{
      display: inline-flex;
      min-width: 82px;
      justify-content: center;
      padding: 5px 10px;
      border-radius: 8px;
      color: #fff;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .severity-critical {{ background: var(--critical); }}
    .severity-high {{ background: var(--high); }}
    .severity-medium {{ background: var(--medium); }}
    .severity-low {{ background: var(--low); }}
    .severity-note {{ background: var(--note); }}
    .severity-unknown {{ background: var(--unknown); }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; background: #f2f6fa; }}
    tr:last-child td {{ border-bottom: 0; }}
    td {{ word-break: break-word; }}
    .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    footer {{ margin-top: 32px; color: var(--muted); font-size: 13px; }}
    @media (max-width: 920px) {{
      header {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .two-col {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 560px) {{
      main {{ width: min(100% - 20px, 1240px); padding-top: 18px; }}
      .grid {{ grid-template-columns: 1fr; }}
      th, td {{ padding: 10px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>{esc(title)}</h1>
        <p>{esc(generated_at)}</p>
      </div>
      <span class="pill {top_class}">{esc(top_status)}</span>
    </header>

    <section class="grid" aria-label="Security finding metrics">
      <div class="panel metric"><span>Total</span><strong>{total}</strong></div>
      <div class="panel metric"><span>Critical</span><strong>{counts["critical"]}</strong></div>
      <div class="panel metric"><span>High</span><strong>{counts["high"]}</strong></div>
      <div class="panel metric"><span>Medium</span><strong>{counts["medium"]}</strong></div>
      <div class="panel metric"><span>Low</span><strong>{counts["low"]}</strong></div>
      <div class="panel metric"><span>Note</span><strong>{counts["note"] + counts["unknown"]}</strong></div>
    </section>

    <section class="two-col">
      <div>
        <h2>Scanner Coverage</h2>
        <table>
          <thead><tr><th>Scanner</th><th>Findings</th></tr></thead>
          <tbody>{render_scanner_rows(findings)}</tbody>
        </table>
      </div>
      <div>
        <h2>Parsed Inputs</h2>
        <table>
          <thead><tr><th>SARIF file</th></tr></thead>
          <tbody>{render_source_rows(sarif_files, input_dir)}</tbody>
        </table>
      </div>
    </section>

    <h2>Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Scanner</th><th>Rule</th><th>Message</th><th>Location</th><th>Source</th></tr>
      </thead>
      <tbody>
        {render_finding_rows(findings)}
      </tbody>
    </table>

    <footer>
      Parsed {len(sarif_files)} SARIF files. The table is capped at 500 findings for readability.
    </footer>
  </main>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")


def render_summary(findings: list[dict[str, Any]], sarif_files: list[Path], output_path: Path) -> None:
    counts = severity_counts(findings)
    tool_counts = count_by(findings, "tool")
    lines = [
        "## Security Report",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| SARIF files parsed | {len(sarif_files)} |",
        f"| Findings | {len(findings)} |",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| Notes / Unknown | {counts['note'] + counts['unknown']} |",
        "",
        "Artifact: `ci-html-report` with `index.html` and `security-report.html`.",
    ]
    if tool_counts:
        lines.extend(["", "### Scanner Findings", ""])
        for tool, count in tool_counts.items():
            lines.append(f"- `{tool}`: {count}")
    else:
        lines.extend(["", "No SARIF findings were parsed from the downloaded scan artifacts."])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_index(
    output_path: Path,
    security_report_link: str,
    test_report_link: str,
    coverage_report_link: str,
) -> None:
    generated_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Go Auth Service CI Report</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --ink: #101820;
      --muted: #60707f;
      --line: #dce3ea;
      --accent: #2563eb;
      --shadow: 0 18px 42px rgba(16, 24, 32, 0.10);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: linear-gradient(135deg, #f5f7fb 0%, #edf7f2 50%, #f9eef1 100%);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ width: min(920px, calc(100% - 32px)); margin: 0 auto; padding: 44px 0 56px; }}
    header, a {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    header {{ padding: 28px; }}
    h1 {{ margin: 0; font-size: 32px; letter-spacing: 0; }}
    p {{ margin: 6px 0 0; color: var(--muted); }}
    nav {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }}
    a {{ display: block; padding: 18px; color: var(--ink); text-decoration: none; }}
    a strong {{ display: block; font-size: 18px; }}
    a span {{ display: block; margin-top: 6px; color: var(--muted); }}
    a:focus, a:hover {{ border-color: var(--accent); }}
    @media (max-width: 760px) {{ nav {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Go Auth Service CI Report</h1>
      <p>{esc(generated_at)}</p>
    </header>
    <nav aria-label="CI reports">
      <a href="{esc(test_report_link)}"><strong>Unit Tests</strong><span>Test cases grouped by package</span></a>
      <a href="{esc(coverage_report_link)}"><strong>Coverage</strong><span>Go coverage by file and block</span></a>
      <a href="{esc(security_report_link)}"><strong>Security</strong><span>Vulnerabilities and code scanning SARIF</span></a>
    </nav>
  </main>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Directory containing downloaded SARIF artifacts")
    parser.add_argument("--html", required=True, type=Path, help="Output HTML report path")
    parser.add_argument("--summary", required=True, type=Path, help="Output GitHub summary Markdown path")
    parser.add_argument("--index", type=Path, help="Optional combined CI report index path")
    parser.add_argument("--title", default="Go Auth Service Security Report", help="HTML report title")
    parser.add_argument("--test-report-link", default="tests/reports/test-report.html", help="Relative link to the test HTML report")
    parser.add_argument("--coverage-report-link", default="tests/reports/coverage.html", help="Relative link to the coverage HTML report")
    args = parser.parse_args()

    findings, sarif_files = collect_findings(args.input)
    render_html(findings, sarif_files, args.input, args.html, args.title)
    render_summary(findings, sarif_files, args.summary)
    if args.index:
        security_link = args.html.name if args.html.parent == args.index.parent else args.html.as_posix()
        render_index(args.index, security_link, args.test_report_link, args.coverage_report_link)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
