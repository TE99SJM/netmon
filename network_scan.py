"""Bounded IPv4 discovery on a selected local adapter; no raw sockets required."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import threading
from dataclasses import asdict, dataclass


@dataclass
class NetDevice:
    ip: str
    mac: str
    hostname: str = ""
    interface: str = ""
    connection: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Adapter:
    name: str
    ip: str
    cidr: str

    @property
    def scan_cidr(self) -> str:
        network = ipaddress.IPv4Network(self.cidr)
        # Keep even very large VPN/corporate subnets to at most 254 probes.
        return str(ipaddress.IPv4Network(f"{self.ip}/24", strict=False)) if network.prefixlen < 24 else self.cidr

    @property
    def scope(self) -> str:
        return f"{self.name}|{self.cidr}"

    @property
    def display(self) -> str:
        return f"{self.name}  ·  {self.ip}  ·  scan {self.scan_cidr}"


def _run_hidden(command: list[str], **kwargs):
    if platform.system() == "Windows":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(command, **kwargs)


def classify_interface(name: str) -> str:
    name = name.casefold()
    if any(k in name for k in ("tailscale", "wireguard", "vpn", "vmnet", "vbox", "veth", "docker", "tun", "tap", "hyper-v", "vethernet")):
        return "Virtual / VPN"
    if any(k in name for k in ("wi-fi", "wifi", "wlan", "wlp", "airport")):
        return "Wi-Fi"
    if name.startswith(("eth", "en", "eno", "ens")):
        return "Ethernet"
    if name.startswith(("br", "bridge")):
        return "Bridge"
    return "Local adapter"


def get_adapters() -> list[Adapter]:
    import psutil
    stats = psutil.net_if_stats()
    result = []
    for name, addresses in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        for addr in addresses:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            try:
                interface = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
            except ValueError:
                continue
            if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_unspecified:
                continue
            result.append(Adapter(name, str(interface.ip), str(interface.network)))
    return sorted(result, key=lambda a: (classify_interface(a.name) in ("Virtual / VPN", "Bridge"), a.name.casefold(), a.ip))


def get_local_subnets() -> list[tuple[str, str, str]]:
    return [(a.name, a.ip, a.cidr) for a in get_adapters()]


def _ping_one(ip: str, stop: threading.Event, timeout_ms: int = 700) -> bool:
    if stop.is_set():
        return False
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        return _run_hidden(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ping_sweep(cidr: str, stop: threading.Event, max_workers: int = 32) -> set[str]:
    network = ipaddress.IPv4Network(cidr, strict=False)
    if network.num_addresses > 256:
        raise ValueError("Choose a scan area with at most 256 addresses.")
    ips = [str(h) for h in network.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(lambda ip: _ping_one(ip, stop), ips)
        return {ip for ip, online in zip(ips, results) if online}


_MAC_RE = re.compile(r"(?<![\da-fA-F])(?:[\da-fA-F]{1,2}[:-]){5}[\da-fA-F]{1,2}(?![\da-fA-F])")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _normalize_mac(mac: str) -> str:
    parts = re.split("[:-]", mac.strip())
    if len(parts) != 6 or any(not re.fullmatch(r"[\da-fA-F]{1,2}", p) for p in parts):
        return ""
    value = ":".join(p.zfill(2).upper() for p in parts)
    # All multicast and broadcast hardware addresses are non-device entries.
    return "" if int(parts[0], 16) & 1 or value == "00:00:00:00:00:00" else value


def parse_arp_table(text: str, system: str) -> list[tuple[str, str, str]]:
    rows = []
    hint = ""
    for line in text.splitlines():
        ip_match, mac_match = _IP_RE.search(line), _MAC_RE.search(line)
        # This also accepts localized Windows section headings.
        if system == "Windows" and ip_match and "---" in line and not mac_match:
            hint = ip_match.group()
            continue
        if not ip_match or not mac_match or "FAILED" in line or "INCOMPLETE" in line:
            continue
        mac = _normalize_mac(mac_match.group())
        try:
            address = ipaddress.IPv4Address(ip_match.group())
        except ValueError:
            continue
        if not mac or address.is_multicast or address.is_loopback or address.is_unspecified:
            continue
        if system != "Windows":
            match = re.search(r"\b(?:dev|on)\s+(\S+)", line)
            hint = match.group(1) if match else ""
        rows.append((str(address), mac, hint))
    return rows


def read_arp_table() -> list[tuple[str, str, str]]:
    system = platform.system()
    commands = [["arp", "-a"]] if system == "Windows" else [["arp", "-an"]]
    if system == "Linux":
        commands.insert(0, ["ip", "-4", "neigh"])
    errors = []
    for command in commands:
        try:
            proc = _run_hidden(command, capture_output=True, text=True, errors="replace", timeout=5)
            if proc.returncode == 0:
                return parse_arp_table(proc.stdout, system)
            errors.append(f"{command[0]} exited with code {proc.returncode}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(str(exc))
    raise RuntimeError("Cannot read the local neighbor table. " + "; ".join(errors))


def _resolve_hostname(ip: str) -> str:
    # gethostbyaddr ignores Python socket timeouts on several platforms.
    # dnspython supplies a real per-request deadline without global changes.
    import dns.exception
    import dns.resolver
    import dns.reversename
    try:
        answer = dns.resolver.Resolver().resolve(dns.reversename.from_address(ip), "PTR", lifetime=0.8, search=False)
        return str(answer[0]).rstrip(".")
    except (dns.exception.DNSException, OSError):
        return ""


def scan_network(adapter: Adapter, stop: threading.Event | None = None, resolve_names: bool = True) -> list[NetDevice]:
    stop = stop or threading.Event()
    ping_sweep(adapter.scan_cidr, stop)
    if stop.is_set():
        return []
    scan_area = ipaddress.IPv4Network(adapter.scan_cidr)
    subnet = ipaddress.IPv4Network(adapter.cidr)
    devices = []
    seen = set()
    for ip, mac, hint in read_arp_table():
        address = ipaddress.IPv4Address(ip)
        if address not in scan_area or (subnet.prefixlen < 31 and address in (subnet.network_address, subnet.broadcast_address)):
            continue
        if hint and hint not in (adapter.name, adapter.ip):
            continue
        if (ip, mac) in seen:
            continue
        seen.add((ip, mac))
        devices.append(NetDevice(ip, mac, interface=adapter.name, connection=classify_interface(adapter.name)))
    if resolve_names and not stop.is_set():
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            names = pool.map(lambda d: "" if stop.is_set() else _resolve_hostname(d.ip), devices)
            for device, name in zip(devices, names):
                device.hostname = name
    return sorted(devices, key=lambda d: int(ipaddress.IPv4Address(d.ip)))
