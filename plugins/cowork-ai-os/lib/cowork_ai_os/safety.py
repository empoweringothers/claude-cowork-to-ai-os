"""Filesystem and redaction primitives used by every command.

The module deliberately has no network imports and only opens source material in
read-only mode.  Callers should treat every string read from a capture as
untrusted data.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


class SafetyError(RuntimeError):
    """Raised when an operation would cross a safety boundary."""


FORBIDDEN_SOURCE_PARTS = {
    "cookies",
    "indexeddb",
    "local storage",
    "localstorage",
    "session storage",
    "sessionstorage",
    "credentials",
    "credential",
    "authentication",
    "auth",
    "oauth",
    "tokens",
    "keychain",
}

FORBIDDEN_FILE_NAMES = {
    "cookies",
    "cookies-journal",
    "login data",
    "login data-journal",
    "web data",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".mcp.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".credentials",
    ".credentials.json",
    "credentials.json",
    "credential.json",
    "buddy-tokens.json",
    "buddy_tokens.json",
    "oauth.json",
    "tokens.json",
    "auth.json",
    "authentication.json",
}

FORBIDDEN_CREDENTIAL_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx"}
FORBIDDEN_CREDENTIAL_COMPACT_NAMES = {
    "authjson",
    "authenticationjson",
    "buddytokensjson",
    "credentialjson",
    "credentialsjson",
    "oauthjson",
    "tokensjson",
}

WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *("com{}".format(index) for index in range(1, 10)),
    *("lpt{}".format(index) for index in range(1, 10)),
}

ALLOWED_BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".mp3",
    ".wav",
    ".m4a",
    ".mp4",
    ".mov",
}

HAS_SECURE_DIR_FD = (
    os.name != "nt"
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)

# These are intentionally conservative.  False positives are preferable to
# accidentally exporting a credential; the source file is never changed.
_SECRET_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----", re.I), "private-key"),
    (re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{12,}\b"), "api-key"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "aws-access-key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "github-token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
    (re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{8,})\.(?:eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}\b"), "jwt"),
    (
        re.compile(
            r'''(?im)((?:["'])?\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|oauth[_ -]?token|authorization|password|passwd|secret|token)\b(?:["'])?\s*[:=]\s*)(?!["']?\[REDACTED:)(?:"(?:\\.|[^"\r\n]){4,}"|'(?:\\.|[^'\r\n]){4,}'|[^\s,;}{]{4,})'''
        ),
        "assigned-secret",
    ),
    (re.compile(r"(?i)([?&](?:token|api[_-]?key|access[_-]?token|secret)=)[^&#\s]+"), "url-secret"),
]


def is_relative_to(path: Path, parent: Path) -> bool:
    """Python 3.9-compatible ``Path.is_relative_to``."""

    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def contains_forbidden_part(path: Path) -> bool:
    return any(part.casefold() in FORBIDDEN_SOURCE_PARTS for part in path.parts)


def assert_source_root(path: Path) -> Path:
    """Validate a user-selected source root without traversing it."""

    expanded = path.expanduser()
    if contains_forbidden_part(expanded):
        raise SafetyError("source points at a protected browser or credential store")
    try:
        mode = expanded.lstat().st_mode
    except FileNotFoundError as exc:
        raise SafetyError("source root does not exist") from exc
    if stat.S_ISLNK(mode):
        raise SafetyError("source root must not be a symlink")
    if not stat.S_ISDIR(mode):
        raise SafetyError("source root must be a directory")
    return expanded.resolve()


def assert_no_overlap(source: Path, output: Path) -> None:
    """Reject either direction of source/destination containment."""

    src = source.expanduser().resolve()
    dst = output.expanduser().resolve(strict=False)
    if src == dst or is_relative_to(dst, src) or is_relative_to(src, dst):
        raise SafetyError("source and output paths must not overlap")


def ensure_contained_regular(path: Path, root: Path) -> os.stat_result:
    """Return lstat data only for a non-symlink regular file under ``root``."""

    root_real = root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise SafetyError("source file is outside the selected root") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except FileNotFoundError as exc:
            raise SafetyError("source file disappeared during capture") from exc
        if stat.S_ISLNK(mode):
            raise SafetyError("symlinked source paths are not allowed")
    resolved = path.resolve()
    if not is_relative_to(resolved, root_real):
        raise SafetyError("source path escapes the selected root")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SafetyError("source path is not a regular file")
    if info.st_nlink > 1:
        raise SafetyError("hard-linked source files are not allowed")
    return info


def read_regular_bytes(path: Path, root: Path, max_bytes: int) -> bytes:
    """Read a bounded regular file without following its final symlink."""

    before = ensure_contained_regular(path, root)
    if before.st_size > max_bytes:
        raise SafetyError("source file exceeds the configured size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise SafetyError("source path is not a regular file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SafetyError("source file changed during capture")
        chunks: List[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SafetyError("source file exceeds the configured size limit")
        after = os.fstat(fd)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ino != opened.st_ino
            or after.st_nlink != 1
        ):
            raise SafetyError("source file changed while it was being read")
        return data
    finally:
        os.close(fd)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, root: Optional[Path] = None, max_bytes: int = 1024 * 1024 * 1024) -> str:
    if root is not None:
        return sha256_bytes(read_regular_bytes(path, root, max_bytes))
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise SafetyError("path is linked or not a regular file")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ino != opened.st_ino
            or after.st_nlink != 1
        ):
            raise SafetyError("path changed while it was hashed")
    finally:
        os.close(fd)
    return digest.hexdigest()


def redact_text(text: str) -> Tuple[str, List[str]]:
    """Replace likely credentials and return the redaction categories."""

    cleaned = text.replace("\x00", "")
    categories: List[str] = []
    for pattern, category in _SECRET_PATTERNS:
        if pattern.search(cleaned):
            categories.append(category)

            def replacement(match: re.Match[str]) -> str:
                # Preserve assignment/query prefixes so the result remains
                # understandable while never preserving the secret itself.
                if match.lastindex:
                    return match.group(1) + "[REDACTED:SECRET]"
                return "[REDACTED:SECRET]"

            cleaned = pattern.sub(replacement, cleaned)
    return cleaned, sorted(set(categories))


def detect_secrets(data: bytes) -> List[str]:
    """Scan text and binary bytes for printable credential canaries."""

    text = data.decode("utf-8", errors="ignore")
    # Sanitized Markdown escapes brackets.  Normalize the known inert marker
    # so assignment-pattern scanning does not flag our own redaction output.
    text = text.replace(r"\[REDACTED:SECRET\]", "[REDACTED:SECRET]")
    findings: List[str] = []
    for pattern, category in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(category)
    return sorted(set(findings))


def quote_untrusted_markdown(text: str) -> str:
    """Render imported text as inert, visibly quoted reference material."""

    redacted, _ = redact_text(text)
    redacted = "".join(
        character
        if character in {"\n", "\t"} or not unicodedata.category(character).startswith("C")
        else " "
        for character in redacted
    )
    redacted = html.escape(redacted, quote=False)
    redacted = redacted.replace("\\", "\\\\")
    for character in "`*_{}[]()#+!|":
        redacted = redacted.replace(character, "\\" + character)
    lines = redacted.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join("> " + line for line in lines)


def neutralize_markdown_inline(text: str, fallback: str = "", max_length: int = 1000) -> str:
    """Render untrusted metadata as a single inert Markdown/HTML text span."""

    redacted, _ = redact_text(text)
    redacted = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in redacted
    )
    redacted = " ".join(redacted.split())
    redacted = html.escape(redacted, quote=False).replace("\\", "\\\\")
    for character in "`*_{}[]()#+-.!|":
        redacted = redacted.replace(character, "\\" + character)
    return redacted[:max_length] or fallback


def safe_component(value: str, fallback: str = "item", max_length: int = 80) -> str:
    redacted, _ = redact_text(value)
    value = redacted.replace("[REDACTED:SECRET]", "redacted")
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-_")
    if not value:
        value = fallback
    value = value[:max_length]
    if value.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES:
        value = "_" + value
    return value


def is_probably_text(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    sample = data[:8192]
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # Treating extensionless or mislabeled UTF-8 data as text is safer than
    # copying it byte-for-byte because capture will quote and redact it.
    return True


def secure_mkdir(path: Path) -> None:
    """Create missing directory components as 0700 without chmodding user parents."""

    if HAS_SECURE_DIR_FD:
        descriptor = _open_directory_chain(path, create=True)
        os.close(descriptor)
        return

    missing: List[Path] = []
    cursor = path
    while True:
        try:
            mode = cursor.lstat().st_mode
        except FileNotFoundError:
            missing.append(cursor)
            if cursor.parent == cursor:
                raise SafetyError("unable to find an existing output ancestor")
            cursor = cursor.parent
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise SafetyError("output parent must be a real directory")
        break
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o700)


def _lexical_absolute(path: Path) -> Path:
    """Return an absolute normalized path without following filesystem links."""

    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_directory_chain(path: Path, create: bool) -> int:
    """Open a directory by no-follow handles, optionally creating components.

    The caller owns the returned descriptor.  This POSIX path prevents an
    already-approved parent from being swapped to a symlink between validation
    and a destination write.
    """

    absolute = _lexical_absolute(path)
    parts = absolute.parts
    if not parts or not absolute.anchor:
        raise SafetyError("output directory must have an absolute anchor")
    flags = _directory_open_flags()
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in parts[1:]:
            if part in {"", ".", ".."}:
                raise SafetyError("output directory contains an unsafe component")
            created = False
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise SafetyError("output parent does not exist")
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    created = True
                    child = os.open(part, flags, dir_fd=descriptor)
                except (FileExistsError, NotADirectoryError, OSError) as exc:
                    raise SafetyError("output parent changed during creation") from exc
            except (NotADirectoryError, OSError) as exc:
                raise SafetyError("output parent must not contain symlinks") from exc
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise SafetyError("output parent must be a real directory")
            if created:
                os.fchmod(child, 0o700)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def secure_mkdir_fresh(path: Path) -> None:
    """Create one fresh 0700 directory without following parent symlinks."""

    path = _lexical_absolute(path)
    if path.parent == path or not path.name:
        raise SafetyError("output must name a fresh child directory")
    if HAS_SECURE_DIR_FD:
        parent_descriptor = _open_directory_chain(path.parent, create=True)
        try:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent_descriptor)
            except FileExistsError as exc:
                raise SafetyError("output must be a fresh, non-existent destination") from exc
            flags = _directory_open_flags()
            child = os.open(path.name, flags, dir_fd=parent_descriptor)
            try:
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    raise SafetyError("fresh output is not a directory")
                os.fchmod(child, 0o700)
            finally:
                os.close(child)
        finally:
            os.close(parent_descriptor)
        return

    # Windows fallback: recheck the canonical result immediately after create.
    secure_mkdir(path.parent)
    parent_real = path.parent.resolve()
    try:
        os.mkdir(path, 0o700)
    except FileExistsError as exc:
        raise SafetyError("output must be a fresh, non-existent destination") from exc
    try:
        mode = path.lstat().st_mode
        resolved = path.resolve()
    except OSError as exc:
        raise SafetyError("fresh output could not be verified") from exc
    if (
        stat.S_ISLNK(mode)
        or not stat.S_ISDIR(mode)
        or resolved != parent_real / path.name
    ):
        raise SafetyError("fresh output changed during creation")
    os.chmod(path, 0o700)


def secure_write(path: Path, data: bytes) -> None:
    """Create a new 0600 file; callers must provide a fresh destination tree."""

    path = _lexical_absolute(path)
    if HAS_SECURE_DIR_FD:
        parent_descriptor = _open_directory_chain(path.parent, create=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            try:
                fd = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
            except (FileExistsError, NotADirectoryError, OSError) as exc:
                raise SafetyError("destination path changed or already exists") from exc
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise SafetyError("destination file is linked or not regular")
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        finally:
            os.close(parent_descriptor)
        return

    secure_mkdir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def secure_write_text(path: Path, text: str) -> None:
    secure_write(path, text.encode("utf-8"))


def iter_tree_no_symlinks(
    root: Path, max_entries: int = 100000, max_depth: int = 64
) -> Iterator[Path]:
    """Yield a bounded tree without following symlinked directories."""

    stack = [(root, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise SafetyError("capture directory exceeds the traversal depth limit")
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    visited += 1
                    if visited > max_entries:
                        raise SafetyError("capture directory exceeds the traversal entry limit")
                    entries.append(entry)
            entries.sort(key=lambda item: item.name.casefold())
        except OSError as exc:
            raise SafetyError("unable to inspect a capture directory") from exc
        directories: List[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    yield path
                elif entry.is_dir(follow_symlinks=False):
                    directories.append(path)
                    yield path
                else:
                    yield path
            except OSError:
                yield path
        stack.extend((directory, depth + 1) for directory in reversed(directories))


def forbidden_name(path: Path) -> bool:
    folded = path.name.casefold()
    compact = re.sub(r"[^a-z0-9]+", "", folded)
    return (
        folded in FORBIDDEN_FILE_NAMES
        or folded in FORBIDDEN_SOURCE_PARTS
        or compact in FORBIDDEN_CREDENTIAL_COMPACT_NAMES
        or folded == ".env"
        or folded.startswith(".env.")
        or path.suffix.casefold() in FORBIDDEN_CREDENTIAL_SUFFIXES
    )
