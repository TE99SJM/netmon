# NetMon

A Windows desktop app for discovering local IPv4 neighbors and nearby Bluetooth LE devices, with persistent labels, vendor hints, and address-change history.

**[Download NetMon.exe](https://github.com/TE99SJM/netmon/releases/latest/download/NetMon.exe)** · **[All releases](https://github.com/TE99SJM/netmon/releases)**

## Run on Windows

1. Download `NetMon.exe` from Releases, or download the ZIP and extract it.
2. Double-click `NetMon.exe`. Python and administrator access are not required.
3. Select your Wi-Fi or Ethernet adapter and choose **Scan network**. The app starts an initial scan automatically. Use **Bluetooth LE → Scan Bluetooth** for nearby advertising devices.

Windows 10/11, 64-bit. The binary is unsigned, so Windows may show an unknown-publisher/SmartScreen prompt. Download only from this repository's Releases and check `SHA256SUMS.txt` if needed; do not disable security software.

## What is included

- A clean native desktop interface with network, Bluetooth LE, and Activity tabs.
- Adapter selection, bounded scan areas, automatic 30-second rescans, and Stop controls.
- Search by label, IP, MAC, hostname, or vendor; sortable columns and horizontal scrolling.
- Double-click a device to give it a persistent label. Labels follow its MAC/address.
- CSV export of the currently filtered and sorted view, with Unicode and spreadsheet-formula protection.
- Non-blocking address-change notices and a persistent event history.
- Bundled vendor database; **File → Refresh vendor database** downloads a validated update.
- No telemetry or account. Labels and history remain on your computer.

## Data and older copies

Data is saved at `%LOCALAPPDATA%\NetMon`, not next to the executable. Use **File → Open data folder**. Replacing the executable preserves labels and history.

To migrate labels from an old source-based copy, close NetMon and copy your old `monitor.db` into that folder before the first run. If you already have a database there, preserve it first; the app does not merge databases. The new app starts fresh, adapter-scoped IP observations to prevent mixing old network histories. The original archive's private database is deliberately excluded from source and builds.

On Linux the data directory is `$XDG_DATA_HOME/NetMon` (or `~/.local/share/NetMon`); on macOS it is `~/Library/Application Support/NetMon`. Windows is the packaged release target.

## How discovery works

NetMon probes at most 254 addresses in the selected adapter's local IPv4 scan area, then reads the operating system's neighbor/ARP table. For subnets larger than `/24`, the displayed scan area is limited to the `/24` containing your PC. Results can include cached, sleeping, or recently disconnected devices; this is not a guarantee that a device is online. Network isolation and sleeping devices can prevent discovery. It is not an IPv6, routed-network, port, or vulnerability scanner.

“Seen via” identifies **your PC's adapter**. ARP cannot determine whether a remote device is connected by Wi-Fi or Ethernet. DNS names and vendor/device hints are best-effort estimates. An IP reassignment or private/randomized MAC can produce an address-change notice; that notice alone does not establish an intrusion. Scope includes the adapter name and subnet, so moving between two networks that use the same adapter/subnet can still produce benign reassignment notices.

Bluetooth discovers BLE advertisements only, without pairing. Classic-only devices and devices not currently advertising may be absent. The radio must be on. Private addresses may rotate, so a label cannot reliably follow every Bluetooth device. On macOS, the OS supplies private identifiers rather than real MAC addresses.

## Develop or build

Python 3.12 is used in the Windows build.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-build.txt
python -m unittest discover -s tests -v
python app.py --smoke-test smoke-source.json
python -m PyInstaller --clean --noconfirm NetMon.spec
```

Build Windows executables **on Windows**. Output: `dist/NetMon.exe`. To run source directly, use `python app.py`. Linux requires Tk and `iproute2` or `arp`; BLE additionally needs BlueZ.

The GitHub Actions workflow runs the regression suite, a source integration test, and **two independent launches of the packaged executable**. It creates a new versioned release only after all checks pass. Existing release assets are never silently overwritten. The smoke test uses synthetic devices: it verifies GUI loading, backend imports, worker results, search, sorting, labeling, export, history, shutdown, and persistence. It does not establish compatibility with every physical network adapter or Bluetooth radio.

When releasing another version, update `app_paths.py`, `version_info.txt`, and `RELEASE_NOTES.md`. Push to `main` or run the workflow manually. The build includes dependency versions and validation reports in the release.

## Attribution

Based on the user's `netmon_fixed` app. Original vendor data attribution is preserved. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and data notices. Application source retains the original personal-use designation.
