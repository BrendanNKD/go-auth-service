#!/usr/bin/env python3
"""Render Go test JSON and coverage data into GitHub-friendly reports."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
from pathlib import Path
from typing import Any


FINAL_TEST_ACTIONS = {"pass", "fail", "skip"}
FINAL_PACKAGE_ACTIONS = {"pass", "fail", "skip"}


def pct(part: int | float, whole: int | float) -> float:
    return 0.0 if whole == 0 else (float(part) / float(whole)) * 100.0


def fmt_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}%"


def css_pct(value: float) -> str:
    return f"{max(0.0, min(value, 100.0)):.2f}%"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def read_test_events(path: Path) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], 0

    events: list[dict[str, Any]] = []
    invalid_lines = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if isinstance(event, dict):
            events.append(event)
    return events, invalid_lines


def parse_test_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    packages: dict[str, dict[str, Any]] = {}

    for event in events:
        package_name = str(event.get("Package") or "unknown")
        action = str(event.get("Action") or "")
        test_name = event.get("Test")
        elapsed = event.get("Elapsed")
        output = event.get("Output")

        package = packages.setdefault(
            package_name,
            {
                "name": package_name,
                "status": "unknown",
                "elapsed": None,
                "tests": {},
                "output": [],
            },
        )

        if output and len(package["output"]) < 120:
            package["output"].append(str(output).rstrip())

        if test_name:
            test = package["tests"].setdefault(
                str(test_name),
                {
                    "name": str(test_name),
                    "status": "running",
                    "elapsed": None,
                    "output": [],
                },
            )
            if output and len(test["output"]) < 80:
                test["output"].append(str(output).rstrip())
            if action in FINAL_TEST_ACTIONS:
                test["status"] = action
                test["elapsed"] = elapsed
            elif action == "run" and test["status"] == "unknown":
                test["status"] = "running"

        if not test_name and action in FINAL_PACKAGE_ACTIONS:
            package["status"] = action
            package["elapsed"] = elapsed

    tests: list[dict[str, Any]] = []
    for package in packages.values():
        package_tests = list(package["tests"].values())
        package["test_count"] = len(package_tests)
        package["passed"] = sum(1 for test in package_tests if test["status"] == "pass")
        package["failed"] = sum(1 for test in package_tests if test["status"] == "fail")
        package["skipped"] = sum(1 for test in package_tests if test["status"] == "skip")
        tests.extend({**test, "package": package["name"]} for test in package_tests)

        if package["status"] == "unknown":
            if package["failed"]:
                package["status"] = "fail"
            elif package_tests and package["passed"] + package["skipped"] == len(package_tests):
                package["status"] = "pass"

    return {
        "packages": dict(sorted(packages.items())),
        "tests": sorted(tests, key=lambda item: (item["package"], item["name"])),
    }


def parse_coverage(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "total_statements": 0,
        "covered_statements": 0,
        "percent": None,
        "files": {},
        "packages": {},
    }
    if not path.exists():
        return result

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("mode:"):
            continue

        try:
            location, statements_raw, count_raw = line.rsplit(" ", 2)
            file_name = location.split(":", 1)[0]
            statement_count = int(statements_raw)
            execution_count = int(count_raw)
        except ValueError:
            continue

        covered = statement_count if execution_count > 0 else 0
        package_name = str(Path(file_name).parent).replace("\\", "/")
        if package_name == ".":
            package_name = file_name.split("/", 1)[0] if "/" in file_name else "."

        for bucket_name, key in (("files", file_name), ("packages", package_name)):
            bucket = result[bucket_name].setdefault(
                key,
                {
                    "name": key,
                    "total_statements": 0,
                    "covered_statements": 0,
                    "percent": None,
                },
            )
            bucket["total_statements"] += statement_count
            bucket["covered_statements"] += covered

        result["total_statements"] += statement_count
        result["covered_statements"] += covered

    for group in (result["files"], result["packages"]):
        for item in group.values():
            item["percent"] = pct(item["covered_statements"], item["total_statements"])

    if result["total_statements"]:
        result["percent"] = pct(result["covered_statements"], result["total_statements"])
    return result


def duration(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.2f}s"
    except (TypeError, ValueError):
        return str(value)


def status_label(status: str) -> str:
    labels = {
        "pass": "Passed",
        "fail": "Failed",
        "skip": "Skipped",
        "running": "Incomplete",
        "unknown": "Unknown",
    }
    return labels.get(status, status.title())


def status_class(status: str) -> str:
    return {
        "pass": "status-pass",
        "fail": "status-fail",
        "skip": "status-skip",
    }.get(status, "status-unknown")


def coverage_for_package(package_name: str, coverage: dict[str, Any]) -> float | None:
    coverage_packages = coverage["packages"]
    candidates = [
        package_name,
        package_name.replace("auth-service", "."),
        package_name.removeprefix("auth-service/"),
    ]
    for candidate in candidates:
        item = coverage_packages.get(candidate)
        if item:
            return item["percent"]
    return None


def render_package_rows(report: dict[str, Any], coverage: dict[str, Any]) -> str:
    rows: list[str] = []
    for package in report["packages"].values():
        coverage_percent = coverage_for_package(package["name"], coverage)
        rows.append(
            "<tr>"
            f"<td><span class=\"pill {status_class(package['status'])}\">{esc(status_label(package['status']))}</span></td>"
            f"<td>{esc(package['name'])}</td>"
            f"<td>{package['test_count']}</td>"
            f"<td>{package['passed']}</td>"
            f"<td>{package['failed']}</td>"
            f"<td>{package['skipped']}</td>"
            f"<td>{duration(package['elapsed'])}</td>"
            f"<td>{fmt_pct(coverage_percent)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_test_details(report: dict[str, Any]) -> str:
    sections: list[str] = []
    for package in report["packages"].values():
        tests = sorted(package["tests"].values(), key=lambda item: item["name"])
        open_attr = " open" if package["failed"] else ""
        if tests:
            rows = "\n".join(
                "<tr>"
                f"<td><span class=\"pill {status_class(test['status'])}\">{esc(status_label(test['status']))}</span></td>"
                f"<td>{esc(test['name'])}</td>"
                f"<td>{duration(test['elapsed'])}</td>"
                "</tr>"
                for test in tests
            )
        else:
            rows = "<tr><td colspan=\"3\">No individual test cases were reported for this package.</td></tr>"

        sections.append(
            f"<details{open_attr}>"
            f"<summary><strong>{esc(package['name'])}</strong><span>{package['passed']} pass / {package['failed']} fail / {package['skipped']} skip</span></summary>"
            "<table><thead><tr><th>Status</th><th>Test</th><th>Time</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            "</details>"
        )
    return "\n".join(sections)


def render_failures(report: dict[str, Any]) -> str:
    failures = [test for test in report["tests"] if test["status"] == "fail"]
    if not failures:
        return "<p class=\"quiet\">No failing tests in this run.</p>"

    blocks: list[str] = []
    for test in failures[:12]:
        output = "\n".join(line for line in test["output"] if line).strip()
        if not output:
            output = "No test output was captured for this failure."
        blocks.append(
            "<article class=\"failure\">"
            f"<h3>{esc(test['name'])}</h3>"
            f"<p>{esc(test['package'])}</p>"
            f"<pre>{esc(output[-4000:])}</pre>"
            "</article>"
        )
    return "\n".join(blocks)


def render_html(
    report: dict[str, Any],
    coverage: dict[str, Any],
    invalid_lines: int,
    output_path: Path,
) -> None:
    tests = report["tests"]
    total = len(tests)
    passed = sum(1 for test in tests if test["status"] == "pass")
    failed = sum(1 for test in tests if test["status"] == "fail")
    skipped = sum(1 for test in tests if test["status"] == "skip")
    generated_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    pass_width = css_pct(pct(passed, total))
    fail_width = css_pct(pct(failed, total))
    skip_width = css_pct(pct(skipped, total))
    if failed:
        overall_status = "Failed"
        overall_class = "status-fail"
    elif total == 0 and invalid_lines:
        overall_status = "Incomplete"
        overall_class = "status-unknown"
    else:
        overall_status = "Passed"
        overall_class = "status-pass"

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Go Auth Service Test Report</title>
  <style>
    :root {{
      --bg: #f6f8fb;
      --panel: #ffffff;
      --ink: #13212b;
      --muted: #5d6b78;
      --line: #d8e0e8;
      --pass: #1f8f5f;
      --fail: #c43d3d;
      --skip: #b7791f;
      --accent: #2563eb;
      --teal: #0f766e;
      --shadow: 0 18px 45px rgba(19, 33, 43, 0.10);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background: linear-gradient(135deg, #f6f8fb 0%, #e9f2f4 52%, #f7edf0 100%);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 34px 0 48px; }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 20px;
      align-items: end;
      padding: 28px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    h1 {{ margin: 0; font-size: 32px; letter-spacing: 0; }}
    h2 {{ margin: 34px 0 14px; font-size: 20px; letter-spacing: 0; }}
    h3 {{ margin: 0 0 6px; font-size: 16px; letter-spacing: 0; }}
    p {{ margin: 6px 0 0; color: var(--muted); }}
    .pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 76px;
      padding: 5px 10px;
      border-radius: 8px;
      color: #fff;
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
    }}
    .status-pass {{ background: var(--pass); }}
    .status-fail {{ background: var(--fail); }}
    .status-skip {{ background: var(--skip); }}
    .status-unknown {{ background: #64748b; }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}
    .metric {{
      padding: 18px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 800; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 30px; line-height: 1.1; }}
    .bar {{
      display: flex;
      height: 15px;
      overflow: hidden;
      margin-top: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #e8eef5;
    }}
    .bar-pass {{ width: {pass_width}; background: var(--pass); }}
    .bar-fail {{ width: {fail_width}; background: var(--fail); }}
    .bar-skip {{ width: {skip_width}; background: var(--skip); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0; background: #f2f6fa; }}
    tr:last-child td {{ border-bottom: 0; }}
    details {{
      margin: 12px 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    summary {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      cursor: pointer;
      padding: 14px 16px;
    }}
    details table {{ border: 0; border-top: 1px solid var(--line); border-radius: 0; box-shadow: none; }}
    .failure {{
      margin-bottom: 14px;
      padding: 16px;
      background: var(--panel);
      border: 1px solid #f1b1b1;
      border-left: 6px solid var(--fail);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    pre {{
      max-height: 360px;
      overflow: auto;
      padding: 14px;
      color: #f8fafc;
      background: #17212b;
      border-radius: 8px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .quiet {{ color: var(--muted); }}
    footer {{ margin-top: 32px; color: var(--muted); font-size: 13px; }}
    @media (max-width: 860px) {{
      header {{ grid-template-columns: 1fr; }}
      .metric-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      h1 {{ font-size: 26px; }}
    }}
    @media (max-width: 560px) {{
      main {{ width: min(100% - 20px, 1180px); padding-top: 18px; }}
      .metric-grid {{ grid-template-columns: 1fr; }}
      th, td {{ padding: 10px; }}
      summary {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Go Auth Service Test Report</h1>
        <p>{esc(generated_at)}</p>
      </div>
      <span class="pill {overall_class}">{overall_status}</span>
    </header>

    <section class="metric-grid" aria-label="Test run metrics">
      <div class="metric"><span>Total tests</span><strong>{total}</strong></div>
      <div class="metric"><span>Passed</span><strong>{passed}</strong></div>
      <div class="metric"><span>Failed</span><strong>{failed}</strong></div>
      <div class="metric"><span>Skipped</span><strong>{skipped}</strong></div>
      <div class="metric"><span>Coverage</span><strong>{fmt_pct(coverage["percent"])}</strong></div>
    </section>

    <div class="bar" aria-label="Test status distribution">
      <div class="bar-pass" title="Passed"></div>
      <div class="bar-fail" title="Failed"></div>
      <div class="bar-skip" title="Skipped"></div>
    </div>

    <h2>Package Health</h2>
    <table>
      <thead>
        <tr><th>Status</th><th>Package</th><th>Tests</th><th>Pass</th><th>Fail</th><th>Skip</th><th>Time</th><th>Coverage</th></tr>
      </thead>
      <tbody>
        {render_package_rows(report, coverage)}
      </tbody>
    </table>

    <h2>Failures</h2>
    {render_failures(report)}

    <h2>Test Cases</h2>
    {render_test_details(report)}

    <footer>
      Parsed {len(report["packages"])} packages and {total} tests. Ignored {invalid_lines} non-JSON log lines.
    </footer>
  </main>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")


def render_markdown_summary(
    report: dict[str, Any],
    coverage: dict[str, Any],
    invalid_lines: int,
    output_path: Path,
) -> None:
    tests = report["tests"]
    total = len(tests)
    passed = sum(1 for test in tests if test["status"] == "pass")
    failed = sum(1 for test in tests if test["status"] == "fail")
    skipped = sum(1 for test in tests if test["status"] == "skip")
    failures = [test for test in tests if test["status"] == "fail"]

    lines = [
        "## Unit Test Report",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Tests | {total} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        f"| Skipped | {skipped} |",
        f"| Packages | {len(report['packages'])} |",
        f"| Coverage | {fmt_pct(coverage['percent'])} |",
        "",
        "Artifacts: `test-report.html`, `coverage.html`, `coverage.txt`, `test-report.json`, `coverage.out`.",
    ]

    if invalid_lines:
        lines.extend(["", f"Note: ignored {invalid_lines} non-JSON log lines from the Go test stream."])

    if failures:
        lines.extend(["", "### Failing Tests", ""])
        for test in failures[:10]:
            lines.append(f"- `{test['package']}` / `{test['name']}`")
    elif total == 0 and invalid_lines:
        lines.extend(["", "No test cases were parsed. Check `test-report.json` for the raw Go test output."])
    else:
        lines.extend(["", "All reported tests passed."])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", required=True, type=Path, help="Path to go test -json output")
    parser.add_argument("--coverage", required=True, type=Path, help="Path to Go coverage profile")
    parser.add_argument("--html", required=True, type=Path, help="Output HTML report path")
    parser.add_argument("--summary", required=True, type=Path, help="Output GitHub summary Markdown path")
    args = parser.parse_args()

    events, invalid_lines = read_test_events(args.json)
    report = parse_test_events(events)
    coverage = parse_coverage(args.coverage)
    render_html(report, coverage, invalid_lines, args.html)
    render_markdown_summary(report, coverage, invalid_lines, args.summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
