"""Copy installed dependency license texts into the distributable notices."""
from importlib import metadata
from pathlib import Path
import shutil
import sys

root=Path(__file__).resolve().parents[1]/'licenses'/'dependencies'
root.mkdir(parents=True,exist_ok=True)
packages={'psutil','bleak','dnspython','pyinstaller','pyinstaller-hooks-contrib','packaging','pefile','pywin32-ctypes','typing-extensions'}
for dist in metadata.distributions():
    name=dist.metadata['Name'].lower().replace('_','-')
    if name not in packages and not name.startswith('winrt-'):
        continue
    for file in dist.files or []:
        if Path(file).name.lower().startswith(('license','copying','notice')) and dist.locate_file(file).is_file():
            target=root/name/Path(file)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(dist.locate_file(file),target)
base=Path(sys.base_prefix)
for source in [base/'LICENSE.txt',base/'LICENSE']:
    if source.is_file():shutil.copy2(source,root/'Python-LICENSE.txt')
for source in (base/'tcl').glob('*/license*'):
    if source.is_file():shutil.copy2(source,root/(source.parent.name+'-'+source.name))
print(f'Collected {len(list(root.rglob("*")))} notice entries.')
