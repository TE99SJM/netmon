"""Keep writable user data outside the executable and its extraction folder."""
from pathlib import Path
import os
import sys

VERSION = "1.0.1"


def resource_path(name: str) -> Path:
    return Path(__file__).resolve().parent / name


def data_directory() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = root / "NetMon"
    path.mkdir(parents=True, exist_ok=True)
    return path
