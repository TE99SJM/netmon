"""Capture a review image using explicitly synthetic devices; no network scan."""
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from PIL import ImageGrab
import app
import network_scan
import bluetooth_scan

with TemporaryDirectory() as folder:
    adapter=network_scan.Adapter('Example Wi-Fi','192.0.2.100','192.0.2.0/24')
    with patch.object(network_scan,'get_adapters',return_value=[adapter]):
        root=app.App(Path(folder),auto_start=False)
    root.auto.set(False);root.schedule()
    rows=[('192.0.2.1','00:11:22:33:44:01','example-router','Home router'),('192.0.2.12','00:11:22:33:44:12','example-server','Media server'),('192.0.2.25','00:11:22:33:44:25','example-nas','Family storage'),('192.0.2.42','02:11:22:33:44:42','example-phone','Phone')]
    for ip,mac,name,label in rows:root.storage.set_label(mac,label,'net')
    root.finish_network([network_scan.NetDevice(ip,mac,name,adapter.name) for ip,mac,name,label in rows],adapter,5.2,None)
    root.finish_bluetooth([bluetooth_scan.BtDevice('02:11:22:33:44:55','Example sensor',-52)],None)
    root.status.set('DEMO VIEW · Synthetic sample devices for interface review')
    root.update();time.sleep(.5)
    x,y=root.winfo_rootx(),root.winfo_rooty()
    ImageGrab.grab(bbox=(x,y,x+root.winfo_width(),y+root.winfo_height())).save('preview-windows.png')
    root.close()
