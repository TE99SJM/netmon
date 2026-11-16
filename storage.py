"""
SQLite-backed persistence for user labels and MAC<->IP history.

Schema
------
labels(mac TEXT PRIMARY KEY, label TEXT, kind TEXT, updated_at REAL)
    `kind` is 'net' or 'bt'. The label is bound to the MAC, not the IP.

ip_history(ip TEXT PRIMARY KEY, mac TEXT, last_seen REAL, first_seen REAL)
    Lets us detect "this IP used to be MAC X, now it's MAC Y" -> alert.

mac_history(mac TEXT PRIMARY KEY, last_ip TEXT, last_seen REAL, first_seen REAL)
    Lets the UI tell you when a labelled device hops to a new IP.

events(id INTEGER PK, ts REAL, kind TEXT, message TEXT)
    Append-only log of MAC-change alerts so the UI can show history.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass


SCHEMA = """
CREATE TABLE IF NOT EXISTS labels (
    mac        TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    kind       TEXT NOT NULL,        -- 'net' or 'bt'
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_history (
    ip         TEXT PRIMARY KEY,
    mac        TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mac_history (
    mac        TEXT PRIMARY KEY,
    last_ip    TEXT,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    kind    TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY(scope, ip)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
"""


@dataclass
class MacChange:
    """A detected change: an IP that previously mapped to old_mac is now new_mac."""
    ip: str
    old_mac: str
    new_mac: str
    label: str  # label of old_mac if any (so user can see what 'moved')


class Storage:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- labels

    def get_label(self, mac: str) -> str:
        if not mac:
            return ""
        with self._lock:
            cur = self._conn.execute(
                "SELECT label FROM labels WHERE mac = ?", (mac.upper(),)
            )
            row = cur.fetchone()
        return row["label"] if row else ""

    def set_label(self, mac: str, label: str, kind: str) -> None:
        if not mac:
            return
        mac = mac.upper()
        now = time.time()
        with self._lock:
            if not label:
                self._conn.execute("DELETE FROM labels WHERE mac = ?", (mac,))
            else:
                self._conn.execute(
                    """
                    INSERT INTO labels(mac, label, kind, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        label = excluded.label,
                        kind  = excluded.kind,
                        updated_at = excluded.updated_at
                    """,
                    (mac, label, kind, now),
                )
            self._conn.commit()

    def all_labels(self) -> dict[str, str]:
        with self._lock:
            cur = self._conn.execute("SELECT mac, label FROM labels")
            return {r["mac"]: r["label"] for r in cur.fetchall()}

    # --------------------------------------------------------- ip <-> mac history

    def update_ip_mac(self, ip: str, mac: str, scope: str = "default") -> MacChange | None:
        """Record (ip,mac). If the IP previously had a different MAC AND that
        old MAC is known in this adapter/subnet scope, return a MacChange."""
        if not ip or not mac:
            return None
        mac = mac.upper()
        now = time.time()
        change: MacChange | None = None
        with self._lock:
            cur = self._conn.execute(
                "SELECT mac, first_seen FROM observations WHERE scope = ? AND ip = ?", (scope, ip)
            )
            row = cur.fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO observations(scope, ip, mac, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (scope, ip, mac, now, now),
                )
            elif row["mac"].upper() != mac:
                # Look up label of the old MAC.
                cur2 = self._conn.execute(
                    "SELECT label FROM labels WHERE mac = ?", (row["mac"].upper(),)
                )
                lbl_row = cur2.fetchone()
                old_label = lbl_row["label"] if lbl_row else ""
                change = MacChange(
                    ip=ip,
                    old_mac=row["mac"].upper(),
                    new_mac=mac,
                    label=old_label,
                )
                self._conn.execute(
                    "UPDATE observations SET mac = ?, last_seen = ? WHERE scope = ? AND ip = ?",
                    (mac, now, scope, ip),
                )
            else:
                self._conn.execute(
                    "UPDATE observations SET last_seen = ? WHERE scope = ? AND ip = ?",
                    (now, scope, ip),
                )
            # Touch mac_history.
            self._conn.execute(
                """
                INSERT INTO mac_history(mac, last_ip, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    last_ip = excluded.last_ip,
                    last_seen = excluded.last_seen
                """,
                (mac, ip, now, now),
            )
            self._conn.commit()
        return change

    def last_seen(self, mac: str) -> float:
        with self._lock:
            cur = self._conn.execute(
                "SELECT last_seen FROM mac_history WHERE mac = ?", (mac.upper(),)
            )
            row = cur.fetchone()
        return float(row["last_seen"]) if row else 0.0

    # -------------------------------------------------------------- events

    def log_event(self, kind: str, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(ts, kind, message) VALUES (?, ?, ?)",
                (time.time(), kind, message),
            )
            self._conn.commit()

    def recent_events(self, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, kind, message FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return list(cur.fetchall())

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value)
            )
            self._conn.commit()
