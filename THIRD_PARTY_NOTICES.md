# Third-party notices

NetMon is based on the user's `netmon_fixed` Python project. The original project described itself as a personal-use project; this update does not introduce a new license grant for the application source.

## Wireshark vendor database

`manuf.txt` is the Wireshark manufacturer database supplied with the original NetMon archive. Its upstream source is <https://www.wireshark.org/download/automated/data/manuf.gz>. Attribution and the original file header are retained. The original project identifies this bundled data as GPLv2; the GPLv2 text is included at `licenses/Wireshark-GPL-2.0.txt`. Wireshark source is available at <https://gitlab.com/wireshark/wireshark>.

## Runtime dependencies

The executable bundles Python, Tcl/Tk, psutil, Bleak, dnspython, and their platform dependencies. PyInstaller provides the executable bootloader. Package metadata is included in the executable, and the build dependency versions and dependency license texts accompany the ZIP download.

- Python: <https://docs.python.org/3/license.html>
- Tcl/Tk: <https://www.tcl-lang.org/software/tcltk/license.html>
- psutil (BSD): <https://github.com/giampaolo/psutil>
- Bleak (MIT): <https://github.com/hbldh/bleak>
- dnspython (ISC): <https://github.com/rthalley/dnspython>
- PyInstaller (GPL with bootloader exception): <https://pyinstaller.org/en/stable/license.html>

No original `monitor.db`, local device labels, or discovery history is distributed with NetMon.
