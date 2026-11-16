"""BLE advertising discovery on a persistent background event loop."""
from __future__ import annotations

import asyncio
import concurrent.futures
import platform
import threading
from dataclasses import asdict, dataclass


@dataclass
class BtDevice:
    address: str
    name: str = ""
    rssi: int | None = None
    address_kind: str = "mac"

    def to_dict(self) -> dict:
        return asdict(self)


def collect_advertisement(found: dict, device, advertisement) -> None:
    address = (device.address or "").upper()
    if not address:
        return
    previous = found.get(address)
    name = advertisement.local_name or device.name or (previous.name if previous else "")
    # Display the latest measurement, not the strongest ever observed.
    rssi = getattr(advertisement, "rssi", None)
    found[address] = BtDevice(address, name, rssi, "uuid" if platform.system() == "Darwin" else "mac")


async def _scan_async(duration: float, stop: threading.Event) -> list[BtDevice]:
    from bleak import BleakScanner
    found = {}
    async with BleakScanner(detection_callback=lambda d, a: collect_advertisement(found, d, a)):
        deadline = asyncio.get_running_loop().time() + duration
        while not stop.is_set() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.1)
    return sorted(found.values(), key=lambda d: d.rssi if d.rssi is not None else -999, reverse=True)


class BluetoothService:
    def __init__(self):
        self._ready = threading.Event()
        self._loop = None
        self._error = None
        self._thread = threading.Thread(target=self._run, name="netmon-bluetooth", daemon=True)
        self._thread.start()

    def _run(self):
        try:
            if platform.system() == "Windows":
                from bleak.backends.winrt.util import uninitialize_sta
                uninitialize_sta()
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        except Exception as exc:
            self._error = exc
            self._ready.set()
            return
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    def scan(self, duration: float, stop: threading.Event) -> list[BtDevice]:
        if not self._ready.wait(5):
            raise RuntimeError("Bluetooth initialization timed out.")
        if self._error:
            raise RuntimeError(f"Bluetooth initialization failed: {self._error}")
        future = asyncio.run_coroutine_threadsafe(_scan_async(duration, stop), self._loop)
        try:
            return future.result(timeout=duration + 20)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise RuntimeError("Bluetooth timed out. Check that the radio is switched on and try again.") from None

    def close(self):
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)


def is_available() -> tuple[bool, str]:
    try:
        import bleak  # noqa: F401
        return True, ""
    except ImportError:
        return False, "Bluetooth support is missing. Reinstall NetMon or install requirements.txt when running from source."
