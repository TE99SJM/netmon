"""Offline integration checks run from source and from the Windows executable."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import traceback
from unittest.mock import patch


def run(report_path):
    report={'ok':False,'checks':[]}
    root=None
    try:
        import app
        import bluetooth_scan
        import dns.resolver
        import network_scan
        import psutil
        from app_paths import VERSION
        from storage import Storage
        report['version']=VERSION
        if __import__('sys').platform=='win32':
            from bleak.backends.winrt.scanner import BleakScannerWinRT
            assert isinstance(network_scan.get_adapters(), list)
            assert isinstance(network_scan.read_arp_table(), list)
            report['checks'].append('Windows adapter enumeration and native ARP command')
        report['checks'].append('Bundled dependencies and platform BLE backend import')
        with TemporaryDirectory(prefix='netmon-smoke-') as folder:
            a=network_scan.Adapter('Example Wi-Fi','192.0.2.100','192.0.2.0/24')
            with patch.object(network_scan,'get_adapters',return_value=[a]):root=app.App(Path(folder),auto_start=False)
            root.auto.set(False);root.schedule()
            root.report_callback_exception=lambda exc,value,tb:(_ for _ in ()).throw(value)
            root.update()
            assert root.oui.count>10000,'Bundled vendor database missing'
            report['checks'].append('Window, tabs, and vendor database load')
            examples=[network_scan.NetDevice('192.0.2.10','00:11:22:33:44:10','example-server',a.name),network_scan.NetDevice('192.0.2.2','00:11:22:33:44:02','example-router',a.name)]
            def pump_until(predicate):
                deadline=time.monotonic()+8
                while not predicate() and time.monotonic()<deadline:root.update();time.sleep(.02)
                assert predicate(),'Background work did not finish'
            with patch.object(network_scan,'scan_network',return_value=examples):
                root.start_network();pump_until(lambda:not root.net_busy)
            assert len(root.net_table.records)==2
            root.net_table.sort_by('ip');assert root.net_table.visible[0]['ip']=='192.0.2.2'
            root.net_table.query.set('server');assert len(root.net_table.visible)==1
            root.net_table.query.set('')
            report['checks'].append('Background network result, numeric sorting, filtering, and reset')
            selected=root.net_table.records[0];root.net_table.tree.selection_set(selected['_key'])
            with patch.object(app.simpledialog,'askstring',return_value='My server'):root.edit_label('net')
            assert root.storage.get_label(selected['mac'])=='My server'
            with patch.object(app.filedialog,'asksaveasfilename',return_value=str(Path(folder)/'devices.csv')):root.export_table(root.net_table,'network')
            assert 'My server' in (Path(folder)/'devices.csv').read_text(encoding='utf-8-sig')
            report['checks'].append('Label editing and CSV export')
            root.finish_network([network_scan.NetDevice(examples[0].ip,'00:11:22:33:44:99','replacement',a.name)],a,.2,None)
            assert root.alert_count.get()=='1' and len(root.events.get_children())==1
            root.ack_all();assert root.alert_count.get()=='0'
            report['checks'].append('MAC-change detection, activity history, and acknowledgement')
            with patch.object(network_scan,'scan_network',side_effect=RuntimeError('Expected smoke-test failure')):
                root.start_network();pump_until(lambda:not root.net_busy)
            assert str(root.net_button['state'])=='normal' and root.status.get()=='Expected smoke-test failure'
            root.nb.select(1);root.update()
            with patch.object(bluetooth_scan.BluetoothService,'scan',return_value=[bluetooth_scan.BtDevice('02:11:22:33:44:55','Example sensor',-52)]):
                root.start_bluetooth();pump_until(lambda:not root.bt_busy)
            assert root.bt_table.records[0]['rssi']==-52
            report['checks'].append('Recoverable network error and background BLE result')
            root.close();root=None
            s=Storage(str(Path(folder)/'monitor.db'));assert s.get_label(selected['mac'])=='My server';s.close()
            report['checks'].append('Clean shutdown and label persistence')
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if root:
            try:root.close()
            except Exception:pass
    Path(report_path).write_text(json.dumps(report,indent=2),encoding='utf-8')
    return 0 if report['ok'] else 1
