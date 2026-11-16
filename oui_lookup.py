"""
OUI (MAC vendor) lookup using the Wireshark `manuf` file.

The manuf file supports three block sizes:
  - 24-bit prefix:  AA:BB:CC
  - 28-bit prefix:  AA:BB:CC:D0/28
  - 36-bit prefix:  AA:BB:CC:DD:E0/36

Vendors are matched longest-prefix-first (36 -> 28 -> 24).

Also provides a `guess_device(vendor, hostname, name)` heuristic that
combines the OUI vendor with hostname / advertised-name keywords to make
a best-guess at what kind of device it is (phone, TV, router, etc).
"""

from __future__ import annotations

import os
import gzip
import io
import tempfile
import re
import urllib.request
from dataclasses import dataclass


MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf.gz"


@dataclass
class VendorRecord:
    short: str
    full: str


class OuiDatabase:
    """Loads the Wireshark manuf file and answers vendor lookups."""

    def __init__(self, manuf_path: str):
        self.manuf_path = manuf_path
        # Three dicts keyed by the integer form of the prefix.
        self._b24: dict[int, VendorRecord] = {}
        self._b28: dict[int, VendorRecord] = {}
        self._b36: dict[int, VendorRecord] = {}
        self.load()

    # ------------------------------------------------------------------ load

    def load(self) -> None:
        self._b24.clear()
        self._b28.clear()
        self._b36.clear()
        if not os.path.exists(self.manuf_path):
            return
        with open(self.manuf_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Wireshark uses TAB-separated columns.
                parts = re.split(r"\t+", line)
                if len(parts) < 2:
                    continue
                prefix = parts[0].strip()
                short = parts[1].strip() if len(parts) >= 2 else ""
                full = parts[2].strip() if len(parts) >= 3 else short
                self._add(prefix, VendorRecord(short=short, full=full))

    def _add(self, prefix: str, rec: VendorRecord) -> None:
        # Prefix may be 'AA:BB:CC' or 'AA:BB:CC:D0/28' style.
        if "/" in prefix:
            base, bits = prefix.split("/", 1)
            try:
                bits_n = int(bits)
            except ValueError:
                return
        else:
            base = prefix
            bits_n = 24
        if bits_n not in (24, 28, 36):
            return
        hexs = base.replace(":", "").replace("-", "").upper()
        if not re.fullmatch(r"[0-9A-F]+", hexs):
            return
        # Pad/truncate to 12 hex chars (48-bit MAC width).
        hexs = (hexs + "000000000000")[:12]
        try:
            value = int(hexs, 16)
        except ValueError:
            return
        # Mask to the top `bits_n` bits.
        mask = ((1 << bits_n) - 1) << (48 - bits_n)
        key = value & mask
        if bits_n >= 36:
            self._b36[key] = rec
        elif bits_n >= 28:
            self._b28[key] = rec
        else:
            self._b24[key] = rec

    # --------------------------------------------------------------- lookup

    @staticmethod
    def _mac_to_int(mac: str) -> int | None:
        if not mac:
            return None
        hexs = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(hexs) != 12:
            return None
        hexs = (hexs + "000000000000")[:12]
        try:
            return int(hexs, 16)
        except ValueError:
            return None

    def lookup(self, mac: str) -> str:
        """Return the best (longest-prefix) vendor name, or '' if unknown."""
        v = self._mac_to_int(mac)
        if v is None:
            return ""
        if (v >> 40) & 0x02:
            return "Private / locally administered"
        # 36-bit
        m36 = ((1 << 36) - 1) << (48 - 36)
        rec = self._b36.get(v & m36)
        if rec:
            return rec.full or rec.short
        # 28-bit
        m28 = ((1 << 28) - 1) << (48 - 28)
        rec = self._b28.get(v & m28)
        if rec:
            return rec.full or rec.short
        # 24-bit
        m24 = ((1 << 24) - 1) << (48 - 24)
        rec = self._b24.get(v & m24)
        if rec:
            return rec.full or rec.short
        # Locally-administered MAC (random / privacy MAC)?
        first_byte = (v >> 40) & 0xFF
        if first_byte & 0x02:
            return "Locally administered (randomized)"
        return ""

    # ----------------------------------------------------------- updater

    def update_from_internet(self) -> tuple[bool, str]:
        """Validate a download before atomically replacing the writable cache."""
        tmp = None
        try:
            req = urllib.request.Request(MANUF_URL, headers={"User-Agent": "NetMon/1.0"})
            limit = 24 * 1024 * 1024
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read(limit + 1)
            if len(data) > limit:
                raise ValueError("Vendor download exceeds the size limit")
            if data.startswith(b"\x1f\x8b"):
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
                    data = zipped.read(limit + 1)
            if not 100_000 <= len(data) <= limit:
                raise ValueError("Vendor download has an unexpected size")
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(self.manuf_path), delete=False) as fh:
                tmp = fh.name
                fh.write(data)
            candidate = OuiDatabase(tmp)
            if candidate.count < 10_000:
                raise ValueError("Downloaded content is not a complete vendor database")
            os.replace(tmp, self.manuf_path)
            self._b24, self._b28, self._b36 = candidate._b24, candidate._b28, candidate._b36
            return True, f"Updated {self.count:,} vendor prefixes."
        except Exception as exc:
            return False, f"Update failed: {exc}"
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)

    @property
    def count(self) -> int:
        return len(self._b24) + len(self._b28) + len(self._b36)


# ----------------------------------------------------------- device guesser

# Vendor-name keyword -> guessed device kind.
_VENDOR_KEYWORDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bapple\b", re.I), "Apple device (iPhone/iPad/Mac)"),
    (re.compile(r"\bsamsung\b", re.I), "Samsung device"),
    (re.compile(r"\b(google|nest)\b", re.I), "Google / Nest device"),
    (re.compile(r"\bamazon\b", re.I), "Amazon device (Echo/Fire)"),
    (re.compile(r"\broku\b", re.I), "Roku streaming device"),
    (re.compile(r"\bsonos\b", re.I), "Sonos speaker"),
    (re.compile(r"\bring\b", re.I), "Ring camera/doorbell"),
    (re.compile(r"\bwyze\b", re.I), "Wyze camera"),
    (re.compile(r"\bphilips\s*hue\b|\bsignify\b", re.I), "Philips Hue lighting"),
    (re.compile(r"\bespressif\b", re.I), "ESP32/ESP8266 IoT board"),
    (re.compile(r"\btuya\b", re.I), "Tuya smart device"),
    (re.compile(r"\b(tp[\s\-]?link|mercury|tplink)\b", re.I), "TP-Link router/AP"),
    (re.compile(r"\bnetgear\b", re.I), "Netgear router/AP"),
    (re.compile(r"\bubiquiti\b", re.I), "Ubiquiti network gear"),
    (re.compile(r"\b(cisco|meraki)\b", re.I), "Cisco/Meraki network gear"),
    (re.compile(r"\barris\b|\btechnicolor\b|\bcommscope\b", re.I), "ISP modem/gateway"),
    (re.compile(r"\b(asus|asustek)\b", re.I), "ASUS device"),
    (re.compile(r"\bdell\b", re.I), "Dell computer"),
    (re.compile(r"\bhp\b|\bhewlett\b", re.I), "HP computer/printer"),
    (re.compile(r"\blenovo\b", re.I), "Lenovo computer"),
    (re.compile(r"\bmicrosoft\b", re.I), "Microsoft device (Xbox/Surface)"),
    (re.compile(r"\bsony\b", re.I), "Sony device (PlayStation/TV)"),
    (re.compile(r"\bnintendo\b", re.I), "Nintendo console"),
    (re.compile(r"\blg\b", re.I), "LG device (TV/appliance)"),
    (re.compile(r"\bvizio\b", re.I), "Vizio TV"),
    (re.compile(r"\btcl\b|\bhisense\b", re.I), "TCL/Hisense TV"),
    (re.compile(r"\bhuawei\b", re.I), "Huawei device"),
    (re.compile(r"\bxiaomi\b", re.I), "Xiaomi device"),
    (re.compile(r"\bintel\b", re.I), "Intel Wi-Fi adapter (PC/laptop)"),
    (re.compile(r"\brealtek\b", re.I), "Realtek adapter (PC/IoT)"),
    (re.compile(r"\bbroadcom\b", re.I), "Broadcom adapter"),
    (re.compile(r"\bfitbit\b|\bgarmin\b", re.I), "Fitness wearable"),
    (re.compile(r"\bbose\b|\bjbl\b|\bharman\b", re.I), "Audio device"),
    (re.compile(r"\bcanon\b|\bbrother\b|\bepson\b", re.I), "Printer"),
]

# Hostname / advertised-name keywords -> override guesses (these win over vendor).
_NAME_KEYWORDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"iphone", re.I), "iPhone"),
    (re.compile(r"ipad", re.I), "iPad"),
    (re.compile(r"macbook|imac|mac\-mini|macmini", re.I), "Mac computer"),
    (re.compile(r"airpods", re.I), "AirPods"),
    (re.compile(r"watch", re.I), "Smart watch"),
    (re.compile(r"galaxy|sm\-", re.I), "Samsung Galaxy"),
    (re.compile(r"pixel", re.I), "Google Pixel"),
    (re.compile(r"echo|alexa", re.I), "Amazon Echo"),
    (re.compile(r"firetv|fire\-tv|fire\stv", re.I), "Amazon Fire TV"),
    (re.compile(r"roku", re.I), "Roku"),
    (re.compile(r"chromecast|chrome\-cast", re.I), "Chromecast"),
    (re.compile(r"nest", re.I), "Nest device"),
    (re.compile(r"hue\-bridge|philips\-hue", re.I), "Philips Hue bridge"),
    (re.compile(r"printer|hp\-print|brother|epson|canon", re.I), "Printer"),
    (re.compile(r"xbox", re.I), "Xbox"),
    (re.compile(r"playstation|ps5|ps4", re.I), "PlayStation"),
    (re.compile(r"switch", re.I), "Nintendo Switch"),
    (re.compile(r"camera|cam\b|ipcam", re.I), "IP camera"),
    (re.compile(r"router|gateway|modem", re.I), "Router/Gateway"),
    (re.compile(r"ap\b|access\-point", re.I), "Wi-Fi access point"),
    (re.compile(r"esp\-|esp32|esp8266", re.I), "ESP32/ESP8266 board"),
]


def guess_device(vendor: str, hostname: str = "", advertised_name: str = "") -> str:
    """Best-effort guess of what a device is. Returns '' if no guess."""
    # Hostname / advertised name wins.
    for src in (hostname or "", advertised_name or ""):
        for pat, label in _NAME_KEYWORDS:
            if pat.search(src):
                return label
    if vendor:
        for pat, label in _VENDOR_KEYWORDS:
            if pat.search(vendor):
                return label
    return ""
