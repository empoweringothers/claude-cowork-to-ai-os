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
    absolute = _lexical_absolute(expanded)
    anchor = Path(absolute.anchor)
    cursor = anchor
    mode = cursor.lstat().st_mode
    components = absolute.parts[1:]
    for index, part in enumerate(components):
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except FileNotFoundError as exc:
            raise SafetyError("source root does not exist") from exc
        if stat.S_ISLNK(mode):
            # macOS exposes ordinary temporary paths through the root-owned
            # top-level ``/var`` alias.  Such a non-final filesystem alias is
            # outside user control; every lower or final symlink is rejected.
            if cursor.parent == anchor and index < len(components) - 1:
                continue
            raise SafetyError("source root must not contain symlinks")
    if not stat.S_ISDIR(mode):
        raise SafetyError("source root must be a directory")
    resolved = absolute.resolve()
    if contains_forbidden_part(resolved):
        raise SafetyError("source points at a protected browser or credential store")
    return resolved


def assert_no_overlap(source: Path, output: Path) -> None:
    """Reject either direction of source/destination containment."""

    src = source.expanduser().resolve()
    dst = output.expanduser().resolve(strict=False)
    if src == dst or is_relative_to(dst, src) or is_relative_to(src, dst):
        raise SafetyError("source and output paths must not overlap")


def _source_file_identity(info: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    """Return the complete metadata identity used around a source read."""

    return (
        stat.S_IFMT(info.st_mode),
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _source_file_comparable_identity(
    info: os.stat_result,
) -> Tuple[int, int, int, int, int, int, int]:
    """Return identity comparable between path and handle stat calls.

    Windows path ``lstat`` may expose creation time through ``st_ctime`` while
    handle ``fstat`` exposes change time.  Normalize only that non-comparable
    field; handle-to-handle and path-to-path race checks keep the exact ctime.
    """

    identity = _source_file_identity(info)
    if os.name == "nt":
        return identity[:5] + (0,) + identity[6:]
    return identity


def ensure_contained_regular(
    path: Path,
    root: Path,
    *,
    allow_source_hardlinks: bool = False,
) -> os.stat_result:
    """Return lstat data only for a safe regular file under ``root``.

    Hardlinks remain forbidden unless a caller deliberately opts in by keyword.
    The opt-in is a low-level primitive; capture policy restricts its use to
    explicitly selected session upload directories.
    """

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
    if info.st_nlink > 1 and not allow_source_hardlinks:
        raise SafetyError("hard-linked source files are not allowed")
    if info.st_nlink > 1 and not HAS_SECURE_DIR_FD:
        raise SafetyError(
            "hard-linked source files require secure no-follow descriptor traversal"
        )
    return info


def _open_contained_readonly(path: Path, root: Path) -> int:
    """Open a contained file through no-follow directory descriptors.

    The caller owns the returned descriptor. This path is required for the
    narrow source-hardlink opt-in so an intermediate directory cannot be
    swapped to a symlink between validation and open.
    """

    if not HAS_SECURE_DIR_FD:
        raise SafetyError(
            "hard-linked source files require secure no-follow descriptor traversal"
        )
    root_absolute = _lexical_absolute(root)
    path_absolute = _lexical_absolute(path)
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise SafetyError("source file is outside the selected root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SafetyError("source path contains an unsafe component")

    descriptor = _open_directory_chain(root_absolute, create=False)
    try:
        flags = _directory_open_flags()
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except (FileNotFoundError, NotADirectoryError, OSError) as exc:
                raise SafetyError("source parent changed during capture") from exc
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise SafetyError("source parent is not a real directory")
            os.close(descriptor)
            descriptor = child

        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            opened = os.open(relative.parts[-1], file_flags, dir_fd=descriptor)
        except (FileNotFoundError, NotADirectoryError, OSError) as exc:
            raise SafetyError("source file changed during capture") from exc
        return opened
    finally:
        os.close(descriptor)


def _open_windows_contained_readonly(
    path: Path, root: Path, *, metadata_only: bool = False
) -> int:
    """Open a Windows file and prove its handle resolves beneath ``root``.

    Windows does not expose POSIX ``dir_fd`` traversal. A path can therefore
    change through a parent junction or symlink between validation and open.
    ``GetFinalPathNameByHandleW`` binds the containment decision to the actual
    opened handle, which is stable even if the pathname changes again.
    ``metadata_only`` requests only ``FILE_READ_ATTRIBUTES`` so approval
    previews can inspect change metadata without opening the body for reading.
    """

    if os.name != "nt":
        raise SafetyError("Windows handle containment is unavailable")
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
    except ImportError as exc:  # pragma: no cover - Windows stdlib invariant
        raise SafetyError("Windows handle containment is unavailable") from exc

    root_absolute = _lexical_absolute(root)
    path_absolute = _lexical_absolute(path)
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise SafetyError("source file is outside the selected root") from exc
    if (
        not relative.parts
        or any(part in {"", ".", ".."} or ":" in part for part in relative.parts)
    ):
        raise SafetyError("source path contains an unsafe component")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    get_final_path.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    file_read_attributes = 0x00000080
    share_read_write_delete = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    file_attribute_normal = 0x00000080
    # Resolve the trust anchor before opening the file. Never re-resolve it
    # afterward: a parent junction could otherwise be swapped for both calls,
    # making an outside file and a newly outside-looking root agree.
    root_name = os.path.normcase(os.path.abspath(str(root_absolute.resolve())))
    handle = create_file(
        str(path_absolute),
        file_read_attributes if metadata_only else generic_read,
        share_read_write_delete,
        None,
        open_existing,
        file_attribute_normal,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        raise SafetyError("source file changed during capture")

    transferred = False
    try:
        buffer_size = 32768
        buffer = ctypes.create_unicode_buffer(buffer_size)
        length = get_final_path(handle, buffer, buffer_size, 0)
        if not length or length >= buffer_size:
            raise SafetyError("source file handle could not be contained")
        final_name = buffer.value
        if final_name.startswith("\\\\?\\UNC\\"):
            final_name = "\\\\" + final_name[8:]
        elif final_name.startswith("\\\\?\\"):
            final_name = final_name[4:]
        opened_name = os.path.normcase(os.path.abspath(final_name))
        try:
            common = os.path.commonpath((root_name, opened_name))
        except ValueError as exc:
            raise SafetyError("source file handle escapes the selected root") from exc
        if common != root_name:
            raise SafetyError("source file handle escapes the selected root")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
        )
        descriptor = msvcrt.open_osfhandle(int(handle), flags)
        transferred = True
        return descriptor
    finally:
        if not transferred:
            close_handle(handle)


def _windows_file_change_time_100ns(descriptor: int) -> int:
    """Return the NTFS change timestamp for an already-contained file handle.

    Python's Windows ``st_ctime`` is creation time, so it cannot bind an
    approval token to a same-size rewrite whose last-write timestamp is later
    restored. ``FILE_BASIC_INFO.ChangeTime`` is content-free handle metadata
    that advances for that rewrite. Keep its native 100 ns unit explicit.
    """

    if os.name != "nt":
        raise SafetyError("Windows file change metadata is unavailable")
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
    except ImportError as exc:  # pragma: no cover - Windows stdlib invariant
        raise SafetyError("Windows file change metadata is unavailable") from exc

    class FileBasicInfo(ctypes.Structure):
        _fields_ = (
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_file_information = kernel32.GetFileInformationByHandleEx
    get_file_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    get_file_information.restype = wintypes.BOOL

    try:
        handle = msvcrt.get_osfhandle(descriptor)
    except OSError as exc:
        raise SafetyError("Windows file change metadata is unavailable") from exc
    if handle == -1:
        raise SafetyError("Windows file change metadata is unavailable")

    basic = FileBasicInfo()
    # FILE_INFO_BY_HANDLE_CLASS.FileBasicInfo
    if not get_file_information(
        handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)
    ):
        raise SafetyError("Windows file change metadata is unavailable")
    value = int(basic.ChangeTime)
    if value <= 0:
        raise SafetyError("Windows file change metadata is unavailable")
    return value


def source_file_change_marker(
    path: Path,
    root: Path,
    *,
    allow_source_hardlinks: bool = False,
) -> Tuple[str, int]:
    """Return content-free change metadata for an approval boundary.

    POSIX ``ctime`` records an inode change. On Windows, query the actual file
    handle's ``FILE_BASIC_INFO.ChangeTime`` because path ``st_ctime`` is the
    creation timestamp. The handle identity and path identity are checked
    around the query so a link or file swap cannot supply the marker.
    """

    before = ensure_contained_regular(
        path, root, allow_source_hardlinks=allow_source_hardlinks
    )
    if os.name != "nt":
        return ("posix-ctime-ns", before.st_ctime_ns)

    expected_identity = _source_file_identity(before)
    expected_comparable_identity = _source_file_comparable_identity(before)
    descriptor = _open_windows_contained_readonly(
        path, root, metadata_only=True
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _source_file_comparable_identity(opened)
            != expected_comparable_identity
        ):
            raise SafetyError("source file changed during metadata inspection")
        opened_identity = _source_file_identity(opened)
        change_before = _windows_file_change_time_100ns(descriptor)
        after = os.fstat(descriptor)
        path_after = ensure_contained_regular(
            path, root, allow_source_hardlinks=allow_source_hardlinks
        )
        change_after = _windows_file_change_time_100ns(descriptor)
        if (
            _source_file_identity(after) != opened_identity
            or _source_file_identity(path_after) != expected_identity
            or change_after != change_before
        ):
            raise SafetyError("source file changed during metadata inspection")
        return ("windows-change-time-100ns", change_after)
    finally:
        os.close(descriptor)


def read_regular_bytes(
    path: Path,
    root: Path,
    max_bytes: int,
    *,
    allow_source_hardlinks: bool = False,
) -> bytes:
    """Read a bounded regular file without following filesystem links."""

    before = ensure_contained_regular(
        path, root, allow_source_hardlinks=allow_source_hardlinks
    )
    if before.st_size > max_bytes:
        raise SafetyError("source file exceeds the configured size limit")
    expected_identity = _source_file_identity(before)
    expected_comparable_identity = _source_file_comparable_identity(before)
    if HAS_SECURE_DIR_FD:
        fd = _open_contained_readonly(path, root)
    elif os.name == "nt":
        fd = _open_windows_contained_readonly(path, root)
    else:
        raise SafetyError(
            "platform lacks secure source-file handle containment"
        )
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise SafetyError("source path is not a regular file")
        if _source_file_comparable_identity(opened) != expected_comparable_identity:
            raise SafetyError("source file changed during capture")
        opened_identity = _source_file_identity(opened)
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
        if _source_file_identity(after) != opened_identity:
            raise SafetyError("source file changed while it was being read")
        path_after = ensure_contained_regular(
            path, root, allow_source_hardlinks=allow_source_hardlinks
        )
        if _source_file_identity(path_after) != expected_identity:
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
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
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
    # Sanitized Markdown escapes punctuation after the first redaction pass.
    # Normalize those presentation-only escapes before scanning so an inert
    # short value such as ``secret: []`` does not become the four-character
    # false positive ``secret: \[\]``.  Real assigned values remain long enough
    # to match after normalization, and our redaction marker remains exempt.
    text = re.sub(r"\\([`*_{}\[\]()#+!|])", r"\1", text)
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
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
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
