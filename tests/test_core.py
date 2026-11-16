import asyncio
import csv
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import bluetooth_scan
from exporting import write_csv
import network_scan as net
from oui_lookup import OuiDatabase
from storage import Storage

class NetworkTests(unittest.TestCase):
    def test_localized_windows_and_invalid_arp_rows(self):
        text = '''Schnittstelle: 192.168.50.2 --- 0xc
 192.168.50.12  00-11-22-33-44-55 dynamisch
 224.0.0.252    01-00-5e-00-00-fc statisch
 192.168.50.255 ff-ff-ff-ff-ff-ff statisch
 999.2.3.4     00-11-22-33-44-66 dynamic'''
        self.assertEqual(net.parse_arp_table(text, 'Windows'), [('192.168.50.12','00:11:22:33:44:55','192.168.50.2')])
    def test_unpadded_macos_and_linux_failed(self):
        self.assertEqual(net.parse_arp_table('? (10.0.0.5) at 0:1:2:3:4:5 on en0', 'Darwin'), [('10.0.0.5','00:01:02:03:04:05','en0')])
        self.assertEqual(net.parse_arp_table('10.0.0.5 dev eth0 lladdr 00:11:22:33:44:55 FAILED', 'Linux'), [])
    def test_adapter_classification(self):
        self.assertEqual(net.classify_interface('Tailscale'), 'Virtual / VPN')
        self.assertEqual(net.classify_interface('vEthernet (Default Switch)'), 'Virtual / VPN')
        self.assertEqual(net.classify_interface('Wi-Fi'), 'Wi-Fi')
    def test_selected_adapter_and_numeric_order(self):
        a=net.Adapter('Wi-Fi','192.168.50.8','192.168.50.0/24')
        rows=[('192.168.50.10','00:11:22:33:44:10',a.ip),('192.168.50.2','00:11:22:33:44:02',a.ip),('192.168.50.7','00:11:22:33:44:07','Other'),('10.0.0.1','00:11:22:33:44:01','Other')]
        with patch.object(net,'ping_sweep'), patch.object(net,'read_arp_table',return_value=rows):
            self.assertEqual([d.ip for d in net.scan_network(a,resolve_names=False)], ['192.168.50.2','192.168.50.10'])
    def test_large_subnet_and_point_to_point(self):
        self.assertEqual(net.Adapter('LAN','10.4.5.6','10.0.0.0/8').scan_cidr,'10.4.5.0/24')
        a=net.Adapter('LAN','10.0.0.254','10.0.0.254/31')
        with patch.object(net,'ping_sweep'), patch.object(net,'read_arp_table',return_value=[('10.0.0.255','00:11:22:33:44:55','LAN')]):
            self.assertEqual(len(net.scan_network(a,resolve_names=False)),1)
    def test_cancellation_avoids_subprocess(self):
        stop=threading.Event();stop.set()
        with patch.object(net,'_run_hidden') as process:
            self.assertFalse(net._ping_one('192.0.2.1',stop));process.assert_not_called()
    def test_failed_neighbor_read_is_visible(self):
        with patch.object(net,'_run_hidden',side_effect=OSError('missing')):
            with self.assertRaisesRegex(RuntimeError,'Cannot read'):net.read_arp_table()
    def test_dns_timeout_keeps_socket_defaults(self):
        import dns.exception
        import socket
        before=socket.getdefaulttimeout()
        with patch('dns.resolver.Resolver.resolve',side_effect=dns.exception.Timeout):
            self.assertEqual(net._resolve_hostname('192.0.2.1'),'')
        self.assertEqual(socket.getdefaulttimeout(),before)

class StorageTests(unittest.TestCase):
    def test_labels_scoped_changes_and_persistence(self):
        with TemporaryDirectory() as folder:
            path=str(Path(folder)/'test.db');s=Storage(path)
            s.set_label('00:11:22:33:44:55','Living room','net')
            self.assertIsNone(s.update_ip_mac('192.168.1.4','00:11:22:33:44:55','home'))
            self.assertIsNone(s.update_ip_mac('192.168.1.4','00:11:22:33:44:66','work'))
            self.assertEqual(s.update_ip_mac('192.168.1.4','00:11:22:33:44:77','home').label,'Living room')
            self.assertIsNone(s.update_ip_mac('192.168.1.4','00:11:22:33:44:77','home'))
            s.close();s=Storage(path)
            self.assertEqual(s.get_label('00:11:22:33:44:55'),'Living room')
            s.set_label('00:11:22:33:44:55','','net');self.assertEqual(s.all_labels(),{});s.close()

class VendorTests(unittest.TestCase):
    def test_longest_prefix_private_and_invalid(self):
        with TemporaryDirectory() as folder:
            p=Path(folder)/'manuf.txt'
            p.write_text('00:11:22\tBase\tBase Vendor\n00:11:22:30/28\tMid\tMiddle Vendor\n00:11:22:33:40/36\tFine\tFine Vendor\n00:11:22/99\tBad\tIgnored\n02:11:22\tWrong\tWrong Vendor\n')
            d=OuiDatabase(str(p))
            self.assertEqual(d.lookup('00:11:22:33:44:55'),'Fine Vendor')
            self.assertEqual(d.lookup('00:11:22:39:44:55'),'Middle Vendor')
            self.assertEqual(d.lookup('00:11:22:49:44:55'),'Base Vendor')
            self.assertEqual(d.lookup('02:11:22:33:44:55'),'Private / locally administered')
            self.assertEqual(d.lookup('not-a-mac'),'')
    def test_invalid_download_preserves_original(self):
        with TemporaryDirectory() as folder:
            p=Path(folder)/'manuf.txt';p.write_text('00:11:22\tBase\tVendor\n');old=p.read_bytes();d=OuiDatabase(str(p))
            with patch('urllib.request.urlopen') as response:
                response.return_value.__enter__.return_value.read.return_value=b'<html>'*20000
                ok,_=d.update_from_internet()
            self.assertFalse(ok);self.assertEqual(p.read_bytes(),old)
            self.assertEqual(d.lookup('00:11:22:33:44:55'),'Vendor');self.assertEqual(len(list(Path(folder).iterdir())),1)

class BluetoothAndExportTests(unittest.TestCase):
    def test_latest_signal_preserves_name(self):
        found={};device=SimpleNamespace(address='AA:BB:CC:DD:EE:FF',name=None)
        bluetooth_scan.collect_advertisement(found,device,SimpleNamespace(local_name='Sensor',rssi=-40))
        bluetooth_scan.collect_advertisement(found,device,SimpleNamespace(local_name=None,rssi=-80))
        self.assertEqual(found[device.address].name,'Sensor');self.assertEqual(found[device.address].rssi,-80)
    def test_scans_reuse_event_loop(self):
        async def fake(duration,stop):return id(asyncio.get_running_loop())
        service=bluetooth_scan.BluetoothService()
        try:
            with patch.object(bluetooth_scan,'_scan_async',side_effect=fake):
                self.assertEqual(service.scan(.1,threading.Event()),service.scan(.1,threading.Event()))
        finally:service.close();service._thread.join(5)
        self.assertFalse(service._thread.is_alive())
    def test_csv_unicode_formulas_and_numbers(self):
        with TemporaryDirectory() as folder:
            p=Path(folder)/'export.csv';write_csv(p,['Name','Signal'],[['=HYPERLINK("bad")',-70],['Café, TV',None]])
            with p.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.reader(f))
            self.assertTrue(rows[1][0].startswith("'="));self.assertEqual(rows[1][1],'-70');self.assertEqual(rows[2],['Café, TV',''])

if __name__=='__main__':unittest.main()
