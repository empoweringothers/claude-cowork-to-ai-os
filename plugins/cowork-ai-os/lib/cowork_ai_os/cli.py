"""Standard-library command line interface."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence

from . import __version__
from .capture import CaptureLimits, capture_sessions
from .discovery import InventoryResult, discover_sessions
from .doctor import default_cowork_roots, doctor_report
from .safety import (
    SafetyError,
    assert_no_overlap,
    neutralize_markdown_inline,
    secure_mkdir,
    secure_write,
)
from .scaffold import scaffold_ai_os
from .verify import verify_tree


def _json(data: Mapping[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _markdown_inventory(result: InventoryResult) -> str:
    safe = result.agent_safe_dict()
    lines = [
        "# Cowork inventory",
        "",
        "The task metadata file was read, but instruction fields were not consulted or emitted. Standalone transcript, spaces registry, memory, upload, and output files were not opened.",
        "",
        "Sessions: **{}**".format(safe["session_count"]),
        "",
    ]
    for session in safe["sessions"]:
        lines.extend(
            (
                "## Untrusted metadata title: {}".format(_markdown_metadata(str(session["title"]))),
                "",
                "- ID: `{}`".format(session["id"]),
                "- Project (untrusted metadata): {}".format(_markdown_metadata(str(session["project"] or "—"))),
                "- Space (untrusted metadata): {}".format(_markdown_metadata(str(session["space"]["name"] or "—"))),
                "- Space instructions present: {}".format(
                    "unknown (not inspected)"
                    if session["space"]["has_instructions"] is None
                    else ("yes" if session["space"]["has_instructions"] else "no")
                ),
                "- Created: {}".format(session["dates"]["created"] or "—"),
                "- Updated: {}".format(session["dates"]["updated"] or "—"),
                "- Messages (metadata): {}".format(session["counts"]["messages"] if session["counts"]["messages"] is not None else "—"),
                "- Transcript: {} ({:,} bytes)".format(session["transcript"]["kind"] or "not located", session["sizes"]["transcript_bytes"]),
                "- Memory: {} files ({:,} bytes)".format(
                    session["counts"]["memory_files"], session["sizes"]["memory_bytes"]
                ),
                "- Uploads: {} files ({:,} bytes)".format(
                    session["counts"]["uploads"], session["sizes"]["upload_bytes"]
                ),
                "- Outputs: {} files ({:,} bytes)".format(
                    session["counts"]["outputs"], session["sizes"]["output_bytes"]
                ),
                "- Selected folder basenames: {}".format(
                    ", ".join(_markdown_metadata(name) for name in session["selected_folders"]) or "—"
                ),
                "",
            )
        )
    if safe["warnings"]:
        lines.extend(("## Warnings", ""))
        lines.extend("- " + warning for warning in safe["warnings"])
        lines.append("")
    return "\n".join(lines)


def _markdown_metadata(value: str) -> str:
    """Neutralize Markdown, link/image, HTML, and control injection."""

    return neutralize_markdown_inline(value)


def _html_inventory(result: InventoryResult) -> str:
    safe = result.agent_safe_dict()
    rows: List[str] = []
    for session in safe["sessions"]:
        selected = ", ".join(session["selected_folders"]) or "—"
        rows.append(
            "<tr>"
            "<td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td>{}</td><td>{}</td><td>{:,}</td><td>{}</td><td>{}</td>"
            "</tr>".format(
                html.escape(session["id"]),
                html.escape(str(session["title"])),
                html.escape(str(session["project"] or "—")),
                html.escape(str(session["space"]["name"] or "—")),
                (
                    "unknown"
                    if session["space"]["has_instructions"] is None
                    else ("yes" if session["space"]["has_instructions"] else "no")
                ),
                html.escape(str(session["dates"]["updated"] or session["dates"]["created"] or "—")),
                html.escape(str(session["counts"]["messages"] if session["counts"]["messages"] is not None else "—")),
                session["sizes"]["transcript_bytes"],
                html.escape(
                    "M: {} / {:,} B; U: {} / {:,} B; O: {} / {:,} B".format(
                        session["counts"]["memory_files"],
                        session["sizes"]["memory_bytes"],
                        session["counts"]["uploads"],
                        session["sizes"]["upload_bytes"],
                        session["counts"]["outputs"],
                        session["sizes"]["output_bytes"],
                    )
                ),
                html.escape(selected),
            )
        )
    warning_items = "".join("<li>{}</li>".format(html.escape(item)) for item in safe["warnings"])
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cowork inventory</title>
<style>body{{font:15px system-ui,sans-serif;margin:2rem;color:#18202a;background:#fff}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd3db;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#eef2f6}}code{{white-space:nowrap}}.note{{padding:.8rem;background:#fff7d6;border-left:4px solid #c39000}}</style>
</head><body><h1>Cowork inventory</h1>
<p class="note">The task metadata file was read, but instruction fields were not consulted or emitted. Standalone transcript, spaces registry, memory, upload, and output files were not opened.</p>
<p>Sessions: <strong>{count}</strong></p>
<table><thead><tr><th>ID</th><th>Title</th><th>Project</th><th>Space</th><th>Instructions?</th><th>Date</th><th>Messages</th><th>Transcript bytes</th><th>Memory / uploads / outputs</th><th>Selected folder basenames</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Warnings</h2><ul>{warnings}</ul>
</body></html>
""".format(count=safe["session_count"], rows="".join(rows), warnings=warning_items)


def _markdown_report(data: Mapping[str, Any], title: str) -> str:
    lines = ["# " + title, ""]
    for key, value in data.items():
        if isinstance(value, (str, int, bool)) or value is None:
            lines.append(
                "- {}: {}".format(
                    key.replace("_", " ").title(), _markdown_metadata(str(value))
                )
            )
    if isinstance(data.get("roots"), list):
        lines.extend(("", "## Roots", ""))
        for root in data["roots"]:
            display = root.get("path") or "{} ({})".format(root.get("label", "candidate"), root.get("basename", "root"))
            lines.append(
                "- {} — {}".format(
                    _markdown_metadata(str(display)),
                    "usable" if root["usable"] else "not found/usable",
                )
            )
    for key in ("errors", "warnings"):
        values = data.get(key)
        if isinstance(values, list) and values:
            lines.extend(("", "## " + key.title(), ""))
            lines.extend("- " + _markdown_metadata(str(value)) for value in values)
    return "\n".join(lines) + "\n"


def _write_or_print(content: str, output: Optional[str]) -> None:
    if output:
        path = Path(output).expanduser()
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise SafetyError("report output must be a fresh file")
        if not path.parent.exists():
            secure_mkdir(path.parent)
        secure_write(path, content.encode("utf-8"))
    else:
        sys.stdout.write(content)


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowork-ai-os",
        description="Offline, privacy-first Cowork inventory and sanitized capture utility.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor",
        help="locate platform Cowork roots using bounded task-metadata recognition",
    )
    doctor.add_argument(
        "--source",
        "--root",
        action="append",
        default=[],
        help="check only this candidate root; repeat for additional explicit roots",
    )
    doctor.add_argument("--format", choices=("json", "markdown"), default="markdown")
    doctor.add_argument("--output", help="write a fresh report file instead of stdout")
    doctor.add_argument("--agent-safe", action="store_true", help="hide full candidate paths in the report")

    inventory = subparsers.add_parser("inventory", help="produce an agent-safe metadata inventory")
    inventory.add_argument("--source", "--root", required=True, help="Cowork storage root")
    inventory.add_argument("--format", choices=("json", "markdown", "html"), default="json")
    inventory.add_argument("--output", help="write a fresh report file instead of stdout")
    inventory.add_argument("--agent-safe", action="store_true", help="explicitly request the always-on safe field policy")

    capture = subparsers.add_parser("capture", help="sanitize explicitly selected Cowork sessions")
    capture.add_argument("--source", "--root", required=True, help="Cowork storage root")
    capture.add_argument("--session", "--sessions", action="append", required=True, help="opaque session ID or unique prefix; repeat as needed")
    capture.add_argument("--output", required=True, help="fresh destination directory")
    capture.add_argument("--apply", action="store_true", help="write the capture; omission is a zero-write dry run")
    capture.add_argument("--approve-plan", help="approval token printed by the matching dry-run preview")
    capture.add_argument(
        "--include-hardlinked-uploads",
        action="store_true",
        help=(
            "include hardlinked regular files only from explicitly selected "
            "session upload folders; copies by value and is bound to the "
            "preview approval token"
        ),
    )
    capture.add_argument("--max-transcript-bytes", type=_positive_int, default=32 * 1024 * 1024)
    capture.add_argument("--max-messages", type=_positive_int, default=10000)
    capture.add_argument("--max-text-chars", type=_positive_int, default=12 * 1024 * 1024)
    capture.add_argument("--max-files", type=_positive_int, default=100)
    capture.add_argument("--max-file-bytes", type=_positive_int, default=10 * 1024 * 1024)
    capture.add_argument("--max-total-file-bytes", type=_positive_int, default=100 * 1024 * 1024)

    scaffold = subparsers.add_parser("scaffold", help="create a generic AI OS around a verified capture")
    scaffold.add_argument("--capture", required=True, help="existing sanitized capture")
    scaffold.add_argument("--output", required=True, help="fresh destination directory")
    scaffold.add_argument("--profile", choices=("personal", "work"), required=True, help="physically separate AI OS privacy profile")
    scaffold.add_argument("--apply", action="store_true", help="write the scaffold; omission is a zero-write dry run")
    scaffold.add_argument("--approve-plan", help="approval token printed by the matching dry-run preview")

    verify = subparsers.add_parser("verify", help="check hashes, secrets, symlinks, and special files")
    verify.add_argument("path", help="capture or AI OS directory")
    verify.add_argument("--format", choices=("json", "markdown"), default="json")
    verify.add_argument("--output", help="write a fresh report file instead of stdout")
    return parser


def _selectors(values: Sequence[str]) -> List[str]:
    result: List[str] = []
    for value in values:
        result.extend(item.strip() for item in value.split(",") if item.strip())
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    if sys.version_info < (3, 9):
        sys.stderr.write("error: cowork-ai-os requires Python 3.9 or newer\n")
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            if args.output:
                candidates = (
                    [Path(item) for item in args.source]
                    if args.source
                    else default_cowork_roots()
                )
                for candidate in candidates:
                    assert_no_overlap(candidate, Path(args.output))
            result = doctor_report([Path(item) for item in args.source], agent_safe=args.agent_safe)
            content = _json(result) if args.format == "json" else _markdown_report(result, "Cowork doctor")
            _write_or_print(content, args.output)
            return 0
        if args.command == "inventory":
            inventory = discover_sessions(Path(args.source))
            if args.output:
                assert_no_overlap(inventory.source_root, Path(args.output))
            if args.format == "json":
                content = _json(inventory.agent_safe_dict())
            elif args.format == "markdown":
                content = _markdown_inventory(inventory)
            else:
                content = _html_inventory(inventory)
            _write_or_print(content, args.output)
            return 0
        if args.command == "capture":
            limits = CaptureLimits(
                max_transcript_bytes=args.max_transcript_bytes,
                max_messages=args.max_messages,
                max_text_chars=args.max_text_chars,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_file_bytes=args.max_total_file_bytes,
            )
            result = capture_sessions(
                Path(args.source),
                _selectors(args.session),
                Path(args.output),
                apply=args.apply,
                limits=limits,
                approved_plan=args.approve_plan,
                include_hardlinked_uploads=args.include_hardlinked_uploads,
            )
            sys.stdout.write(_json(result))
            return 0
        if args.command == "scaffold":
            result = scaffold_ai_os(
                Path(args.capture),
                Path(args.output),
                profile=args.profile,
                apply=args.apply,
                approved_plan=args.approve_plan,
            )
            sys.stdout.write(_json(result))
            return 0
        if args.command == "verify":
            verification_path = Path(args.path)
            if args.output:
                assert_no_overlap(verification_path, Path(args.output))
            result = verify_tree(verification_path)
            content = _json(result) if args.format == "json" else _markdown_report(result, "Capture verification")
            _write_or_print(content, args.output)
            return 0 if result["ok"] else 1
    except SafetyError as exc:
        sys.stderr.write("error: {}\n".format(str(exc)))
        return 2
    except OSError:
        # Avoid echoing private local paths from platform-specific exceptions.
        sys.stderr.write("error: a filesystem operation failed safely; no source data was changed\n")
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
