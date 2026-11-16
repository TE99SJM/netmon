# Run on Windows: python -m PyInstaller --clean --noconfirm NetMon.spec
from PyInstaller.utils.hooks import collect_submodules, copy_metadata

hidden = collect_submodules('bleak') + collect_submodules('dns')
data = [('manuf.txt', '.'), ('assets/netmon.png', 'assets'), ('THIRD_PARTY_NOTICES.md', '.'), ('licenses', 'licenses')]
for package in ('bleak', 'psutil', 'dnspython'):
    data += copy_metadata(package, recursive=True)
a = Analysis(['app.py'], pathex=[], binaries=[], datas=data, hiddenimports=hidden,
             hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='NetMon', debug=False,
          bootloader_ignore_signals=False, strip=False, upx=False, console=False,
          disable_windowed_traceback=False, icon='assets/netmon.ico', version='version_info.txt')
