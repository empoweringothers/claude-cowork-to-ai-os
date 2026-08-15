#!/usr/bin/env python3
"""Validate the public repository structure without third-party packages."""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "cowork-ai-os"
PRIVATE_PATTERNS = (
    (
        "absolute macOS home path",
        re.compile(("/" + "Users/") + r"(?!example(?:/|$)|me(?:/|$)|username(?:/|$))[A-Za-z0-9._-]+/"),
    ),
    (
        "absolute Windows home path",
        re.compile(r"[A-Za-z]:\\Users\\(?!example(?:\\|$)|me(?:\\|$)|username(?:\\|$))", re.I),
    ),
    (
        "non-example email address",
        re.compile(
            r"\b[A-Z0-9._%+-]+@(?!example\.(?:com|org|net|test)\b)[A-Z0-9.-]+\.[A-Z]{2,}\b",
            re.I,
        ),
    ),
)
REQUIRED = (
    ".claude-plugin/marketplace.json",
    "plugins/cowork-ai-os/.claude-plugin/plugin.json",
    "plugins/cowork-ai-os/skills/import-cowork/SKILL.md",
    "README.md",
    "PRIVACY.md",
    "THREAT-MODEL.md",
    "SUPPORTED-SOURCES.md",
    "SECURITY.md",
    "LICENSE",
    "RELEASE.json",
    "plugins/cowork-ai-os/templates/ai-os/.gitignore",
    "plugins/cowork-ai-os/templates/ai-os/.ai-os/private/.gitignore",
    "plugins/cowork-ai-os/templates/ai-os/Inbox/REVIEW.md",
    "plugins/cowork-ai-os/templates/ai-os/System/permissions.md",
    "plugins/cowork-ai-os/templates/ai-os/System/schema-version.txt",
)
FORBIDDEN_RUNTIME_IMPORTS = {
    "aiohttp",
    "httpx",
    "requests",
    "socket",
    "subprocess",
    "urllib",
    "webbrowser",
}


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def validate() -> list[str]:
    problems: list[str] = []

    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            problems.append(f"missing required file: {relative}")

    try:
        marketplace = load_json(".claude-plugin/marketplace.json")
        plugin = load_json("plugins/cowork-ai-os/.claude-plugin/plugin.json")
        release = load_json("RELEASE.json")
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"invalid manifest JSON: {exc}")
        return problems

    version = str(plugin.get("version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        problems.append("plugin version must use semantic x.y.z form")
    entries = marketplace.get("plugins") or []
    if len(entries) != 1:
        problems.append("marketplace must contain exactly one plugin")
    else:
        entry = entries[0]
        if entry.get("name") != plugin.get("name"):
            problems.append("marketplace and plugin names differ")
        if entry.get("version") != version:
            problems.append("marketplace and plugin versions differ")
        source = ROOT / str(entry.get("source", ""))
        if not source.is_dir():
            problems.append("marketplace plugin source does not exist")
    if release.get("package_version") != version:
        problems.append("RELEASE.json package_version differs from plugin")
    if release.get("release_tag") != f"v{version}":
        problems.append("RELEASE.json tag differs from plugin version")

    skill = PLUGIN / "skills" / "import-cowork" / "SKILL.md"
    if skill.is_file():
        text = skill.read_text(encoding="utf-8")
        if "[TODO" in text:
            problems.append("skill contains a TODO placeholder")
        if not text.startswith("---\n"):
            problems.append("skill frontmatter is missing")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "empoweringothers/claude-cowork-to-ai-os@v" not in readme:
        problems.append("README marketplace install is not pinned to a tag")

    setup_message = (ROOT / "PASTE-INTO-CLAUDE-CODE.txt").read_text(
        encoding="utf-8"
    )
    required_release_markers = {
        "{{GITHUB_RELEASE_URL}}",
        "{{RELEASE_TAG}}",
        "{{GIT_COMMIT_SHA}}",
        "{{RELEASE_ZIP_URL}}",
        "{{RELEASE_ZIP_SHA256}}",
    }
    missing_release_markers = sorted(
        marker for marker in required_release_markers if marker not in setup_message
    )
    if missing_release_markers:
        problems.append(
            "setup message is missing release placeholders: "
            + ", ".join(missing_release_markers)
        )
    if "@{{GIT_COMMIT_SHA}}" in setup_message:
        problems.append("setup message must not use a raw commit as a marketplace ref")
    if "verify_release.py" not in setup_message or "Release ZIP SHA-256" not in setup_message:
        problems.append("setup message must verify the release ZIP and internal manifest")

    workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
        encoding="utf-8"
    )
    for line in workflow.splitlines():
        if "uses: actions/" in line and not re.search(r"@[0-9a-f]{40}(?:\s|$)", line):
            problems.append("GitHub Actions must use full commit pins")

    for path in ROOT.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_symlink():
            problems.append(f"public repository contains a symlink: {path.relative_to(ROOT)}")
            continue
        if not path.is_file():
            continue
        if path.suffix == ".py":
            try:
                parsed_python = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError) as exc:
                problems.append(f"invalid Python: {path.relative_to(ROOT)}: {exc}")
            else:
                if "plugins/cowork-ai-os/lib" in path.as_posix():
                    for node in ast.walk(parsed_python):
                        imported = []
                        if isinstance(node, ast.Import):
                            imported = [alias.name.split(".", 1)[0] for alias in node.names]
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            imported = [node.module.split(".", 1)[0]]
                        for module in imported:
                            if module in FORBIDDEN_RUNTIME_IMPORTS:
                                problems.append(
                                    f"runtime networking/process import is forbidden: {path.relative_to(ROOT)}: {module}"
                                )
        if path.stat().st_size <= 2_000_000:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for label, pattern in PRIVATE_PATTERNS:
                if pattern.search(text):
                    problems.append(
                        f"possible private data in {path.relative_to(ROOT)}: {label}"
                    )

    private = PLUGIN / "templates" / "ai-os" / ".ai-os" / "private"
    if private.is_dir():
        unexpected = [p.name for p in private.iterdir() if p.name != ".gitignore"]
        if unexpected:
            problems.append("template private directory contains data")

    executable = PLUGIN / "bin" / "cowork-ai-os"
    if executable.exists() and os.name != "nt" and not os.access(executable, os.X_OK):
        problems.append("plugins/cowork-ai-os/bin/cowork-ai-os is not executable")

    return problems


def main() -> int:
    problems = validate()
    if problems:
        print("REPOSITORY VALIDATION FAILED")
        for item in problems:
            print(f"- {item}")
        return 1
    print("REPOSITORY VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
