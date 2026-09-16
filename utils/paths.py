from __future__ import annotations

import os
from pathlib import Path

_TLSA_DATA_DIR: Path | None = None


def set_tlsa_data_dir(path: str | os.PathLike) -> None:
    """
    Override the directory used to resolve resources
    """
    global _TLSA_DATA_DIR
    _TLSA_DATA_DIR = Path(path).resolve()


def tlsa_data_dir() -> Path:
    """
    Return the data directory
    """
    if _TLSA_DATA_DIR is not None:
        return _TLSA_DATA_DIR

    env = os.environ.get("TLSA_DATA_DIR")
    if env:
        return Path(env).resolve()

    # fallback to project root (parent of utils/)
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    """
    Resolve directories relative to the data directory
    """
    return tlsa_data_dir().joinpath(*parts)


def ensure_resource_dir(*parts: str) -> Path:
    """
    Resolve a directory path and ensure it exists
    """
    p = resource_path(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p
