import logging
import struct
import re
from pathlib import Path
from typing import Mapping

from rich.logging import RichHandler
import os


def urlsafe_base64(base64_hash: str) -> str:
    """Convert Base64 str to URL-safe Base64 string."""
    return base64_hash.replace("+", "-").replace("/", "_").rstrip("=")


def create_logger(log_level: str) -> logging.Logger:
    """Create rich logger"""
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(rich_tracebacks=True)],
    )
    return logging.getLogger("rich")


def int64_to_float(num: int) -> float:
    """Converts a 64-bit integer to its IEEE 754 double-precision floating-point representation."""
    # Pack the integer into 8 bytes (big-endian) and unpack as double
    return struct.unpack(">d", num.to_bytes(8, byteorder="big"))[0]


def int32_to_float(num: int) -> float:
    """Converts a 32-bit integer to its IEEE 754 double-precision floating-point representation."""
    # Pack the integer into 4 bytes (big-endian) and unpack as double
    return struct.unpack(">f", num.to_bytes(4, byteorder="big"))[0]


def fixed32_to_float(n: int) -> float:
    """Converts a scaled 32-bit signed integer to its floating-point value.

    Args:
        n: A 32-bit signed integer representing a scaled value (x * 10^7)

    Returns:
        The decoded floating-point value (n / 10^7)
    """
    if n > 2147483647:  # 2^31 - 1 (max positive 32-bit signed integer)
        n -= 4294967296  # 2^32

    return n / 10**7


def parse_email(s: str) -> str:
    """Parse email from auth_data"""
    for line in s.split("&"):
        if "Email" in line:
            value = line.split("=")[1]
            return value.replace("%40", "@")
    raise ValueError("No email value in auth_data")


def parse_language(s: str) -> str:
    """Safely parse language from auth_data"""
    for line in s.split("&"):
        if "lang" in line:
            return line.split("=")[1]
    return ""


# --- Album naming helpers ---

def sanitize_album_name(name: str) -> str:
    """Normalize album name for consistency.

    - Replace backslashes with forward slashes
    - Collapse duplicate slashes
    - Trim leading/trailing slashes and whitespace
    - Fallback to 'Uploads' if empty
    """
    cleaned = name.strip().replace("\\", "/")
    cleaned = re.sub(r"/+", "/", cleaned)
    cleaned = cleaned.strip("/")
    return cleaned or "Uploads"


def compute_album_groups(results: Mapping[str, str], album_name: str) -> dict[str, list[str]]:
    """Compute album grouping for uploaded files.

    Supports fixed album names and AUTO/AUTO=<base> modes.

    Args:
        results: Mapping of absolute file paths to media keys.
        album_name: Album mode/name. "AUTO" or "AUTO=/custom/base" for automatic grouping.

    Returns:
        Dict mapping album name -> list of media keys to add.
    """
    # Case 1: fixed album name → all files to the same album
    if album_name and not album_name.startswith("AUTO"):
        return {sanitize_album_name(album_name): list(results.values())}

    # Prepare paths
    all_files_paths = [Path(p) for p in results.keys()]

    # Case 2: AUTO with explicit base path (no filesystem existence required)
    if album_name and album_name.startswith("AUTO="):
        base_str = album_name[5:]
        # Normalize to POSIX-like form and ensure trailing slash
        base_posix = base_str.replace("\\", "/")
        base_posix = re.sub(r"/+", "/", base_posix).rstrip("/") + "/"
        base_leaf = base_posix.strip("/").split("/")[-1] if base_posix.strip("/") else ""

        media_keys_by_album: dict[str, list[str]] = {}
        for file_path_str, media_key in results.items():
            parent_dir = Path(file_path_str).parent.resolve()
            parent_posix = parent_dir.as_posix()
            idx = parent_posix.lower().find(base_posix.lower())
            if idx != -1:
                rel = parent_posix[idx + len(base_posix) :].strip("/")
                album_from_path = base_leaf if rel == "" else rel
            else:
                # Fallback when base is not found within path
                album_from_path = parent_dir.name
            album_from_path = sanitize_album_name(album_from_path)
            media_keys_by_album.setdefault(album_from_path, []).append(media_key)
        return media_keys_by_album

    # Case 3: AUTO without explicit base → use common path among files
    common = os.path.commonpath([str(p) for p in all_files_paths])
    base_path = Path(common)
    if base_path.is_file():
        base_path = base_path.parent

    media_keys_by_album: dict[str, list[str]] = {}
    for file_path_str, media_key in results.items():
        file_path = Path(file_path_str)
        parent_dir = file_path.parent.resolve()
        try:
            relative_path = parent_dir.relative_to(base_path)
            # If parent is exactly the base, album is the base folder name; else album is relative path
            album_from_path = base_path.name if relative_path.parts == () else relative_path.as_posix()
        except ValueError:
            # Fallback when paths are not related
            album_from_path = parent_dir.name
        album_from_path = sanitize_album_name(album_from_path)
        media_keys_by_album.setdefault(album_from_path, []).append(media_key)

    return media_keys_by_album
