"""Command-line interface for the offline phishing email analyzer."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import analyze_message


def read_message(path: Path, max_size_mb: int) -> bytes:
    try:
        size = path.stat().st_size
        if size > max_size_mb * 1024 * 1024:
            raise ValueError(f"input is {size} bytes; limit is {max_size_mb} MiB")
        return path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def render_text(report: dict[str, Any]) -> str:
    message = report["message"]
    lines = ["Offline Phishing Email Analyzer", "",
             f"From domain: {message['from_domain'] or 'not available'}",
             f"Reply-To domain: {message['reply_to_domain'] or 'not available'}",
             f"URLs: {message['url_count']} | Attachments: {message['attachment_count']}",
             f"Findings: {report['findings_count']}", ""]
    if message["url_hosts"]:
        lines.append("URL hosts: " + ", ".join(message["url_hosts"]))
        lines.append("")
    if not report["findings"]:
        lines.append("No configured signal matched. This does not establish that the email is safe.")
    for finding in report["findings"]:
        lines.append(f"[{finding['severity'].upper()}] {finding['rule_id']} · {finding['title']}")
        for item in finding["evidence"]:
            lines.append(f"  Evidence: {item}")
        lines.append("  Triage:")
        lines.extend(f"    - {step}" for step in finding["recommended_triage"])
        lines.append("")
    lines.append(report["disclaimer"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mailtriage",
        description="Analyze a local .eml file without opening URLs or extracting attachments.",
    )
    parser.add_argument("message", type=Path, help="RFC 5322 .eml message file")
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="report format (default: text)")
    parser.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    parser.add_argument("--include-sensitive", action="store_true",
                        help="include full addresses, subject, URLs, and attachment names in the report")
    parser.add_argument("--max-size-mb", type=int, default=25,
                        help="maximum input file size in MiB (default: 25)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.max_size_mb < 1:
        parser.error("--max-size-mb must be at least 1")
    try:
        raw = read_message(args.message, args.max_size_mb)
        report = analyze_message(raw, include_sensitive=args.include_sensitive)
    except (ValueError, OSError) as exc:
        print(f"mailtriage: error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else render_text(report)
    if args.output:
        try:
            if args.message.resolve() == args.output.resolve():
                print("mailtriage: error: output path must not overwrite the input email", file=sys.stderr)
                return 2
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"mailtriage: error: cannot write report: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {report['findings_count']} finding(s) to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
