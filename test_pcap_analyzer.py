import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import os
import argparse
import datetime
import collections
import socket
import io # For capturing print output
import csv # For verifying CSV writing
import dpkt # For constants and basic structures

# Functions and classes to be tested
from pcap_analyzer import (
    format_mac,
    setup_parser,
    PcapReader,
    PacketParser,
    SummaryStatsCollector,
    ProtocolDistributionCollector,
    IpUsageCollector,
    ConversationTracker,
    DnsAnalyzer,
    HttpAnalyzer,
    TlsAnalyzer,
    ReportGenerator
)

# --- Helper to create minimal packet structures for testing PacketParser ---
def create_eth_ip_tcp_packet(src_mac=b'\x00\x01\x02\x03\x04\x05', dst_mac=b'\x06\x07\x08\x09\x0a\x0b',
                             src_ip=b'\x01\x02\x03\x04', dst_ip=b'\x05\x06\x07\x08',
                             sport=12345, dport=80, payload=b'GET / HTTP/1.1\r\n\r\n'):
    tcp_pkt = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)
    tcp_pkt.seq = 1000
    tcp_pkt.ack = 2000
    tcp_pkt.off = 5 # Minimal header size (5 * 4 bytes = 20 bytes)
    # tcp_pkt.sum = ... # dpkt can auto-calculate if needed, or ignore for unit tests

    ip_pkt = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp_pkt)
    ip_pkt.len = len(ip_pkt) # Calculate total length
    # ip_pkt.sum = ...

    eth_pkt = dpkt.ethernet.Ethernet(src=src_mac, dst=dst_mac, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_pkt)
    return bytes(eth_pkt)


class TestPcapAnalyzer(unittest.TestCase):

    def test_format_mac(self):
        self.assertEqual(format_mac(b'\x00\x11\x22\x33\x44\x55'), "00:11:22:33:44:55")

    def test_setup_parser(self):
        parser = setup_parser()
        args = parser.parse_args([
            "test.pcap",
            "--output-dir", "out_dir",
            "--ip-top-n", "5",
            "--dns-top-n", "6",
            "--http-top-n", "7",
            "--tls-top-n", "8",
            "--conv-top-n", "9",
            "--verbose"
        ])
        self.assertEqual(args.pcap_file, "test.pcap")
        self.assertEqual(args.output_dir, "out_dir")
        self.assertEqual(args.ip_top_n, 5)
        self.assertEqual(args.dns_top_n, 6)
        self.assertEqual(args.http_top_n, 7)
        self.assertEqual(args.tls_top_n, 8)
        self.assertEqual(args.conv_top_n, 9)
        self.assertTrue(args.verbose)

        # Test defaults
        args_defaults = parser.parse_args(["test.pcap"])
        self.assertEqual(args_defaults.ip_top_n, 10)
        self.assertIsNone(args_defaults.output_dir) # Default is None in parser setup
        self.assertFalse(args_defaults.verbose)

    @patch('builtins.open', new_callable=mock_open)
    def test_pcap_reader_pcap(self, mock_file_open):
        # Simulate a tiny valid pcap file header and one packet record
        # For simplicity, we'll mock the dpkt.pcap.Reader directly
        mock_pcap_reader_instance = MagicMock(spec=dpkt.pcap.Reader)
        mock_pcap_reader_instance.datalink.return_value = dpkt.pcap.DLT_EN10MB
        mock_pcap_reader_instance.__iter__.return_value = iter([
            (1609459200.0, b'dummy packet data 1'),
            (1609459201.0, b'dummy packet data 2')
        ])

        with patch('dpkt.pcap.Reader', return_value=mock_pcap_reader_instance) as mock_pcap_reader_class, \
             patch('dpkt.pcapng.Reader', side_effect=ValueError("Not pcapng")): # Ensure pcapng fails

            reader = PcapReader("dummy.pcap", verbose=False)
            self.assertIsNotNone(reader.reader)
            self.assertEqual(reader.linktype, dpkt.pcap.DLT_EN10MB)
            self.assertFalse(reader.is_pcapng)

            packets = list(reader)
            self.assertEqual(len(packets), 2)
            self.assertEqual(packets[0][1], b'dummy packet data 1')
            reader.close()
            mock_file_open.assert_called_with("dummy.pcap", 'rb')
            # Ensure the file handle provided by mock_open is closed
            mock_file_open().close.assert_called_once()


    def test_packet_parser_eth_ip_tcp(self):
        parser = PacketParser()
        ts = datetime.datetime.now(datetime.timezone.utc).timestamp()

        src_ip_bytes = socket.inet_aton("1.2.3.4")
        dst_ip_bytes = socket.inet_aton("5.6.7.8")

        # Construct a simple Ethernet/IP/TCP packet using dpkt
        tcp_payload = b"Hello TCP"
        tcp_segment = dpkt.tcp.TCP(sport=12345, dport=80, data=tcp_payload, off=5, flags=dpkt.tcp.TH_SYN)
        ip_packet = dpkt.ip.IP(src=src_ip_bytes, dst=dst_ip_bytes, p=dpkt.ip.IP_PROTO_TCP, data=tcp_segment, len=20+20+len(tcp_payload), v=4) # Simplified length
        eth_frame_bytes = bytes(dpkt.ethernet.Ethernet(src=b'\x01\x02\x03\x04\x05\x06', dst=b'\x07\x08\x09\x0a\x0b\x0c', type=dpkt.ethernet.ETH_TYPE_IP, data=ip_packet))

        parsed = parser.parse_packet(ts, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNone(parsed['error'])
        self.assertIsNotNone(parsed['eth'])
        self.assertEqual(parsed['eth']['src_mac'], "01:02:03:04:05:06")
        self.assertIsNotNone(parsed['ip'])
        self.assertEqual(parsed['ip']['src_ip_str'], "1.2.3.4")
        self.assertEqual(parsed['ip']['dst_ip_str'], "5.6.7.8")
        self.assertEqual(parsed['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        self.assertIsNotNone(parsed['transport'])
        self.assertEqual(parsed['transport']['type'], 'TCP')
        self.assertEqual(parsed['transport']['src_port'], 12345)
        self.assertEqual(parsed['transport']['dst_port'], 80)
        self.assertEqual(parsed['transport']['flags'], dpkt.tcp.TH_SYN)
        self.assertEqual(parsed['payload'], tcp_payload)

    def test_summary_stats_collector(self):
        collector = SummaryStatsCollector()
        ts1 = datetime.datetime(2023,1,1,10,0,0, tzinfo=datetime.timezone.utc)
        ts2 = datetime.datetime(2023,1,1,10,0,10, tzinfo=datetime.timezone.utc) # 10 seconds later

        collector.process_packet(ts1, 100, "Ethernet")
        collector.process_packet(ts2, 150, "Ethernet")

        results = collector.get_results()
        self.assertEqual(results['total_packets'], 2)
        self.assertEqual(results['total_bytes'], 250)
        self.assertEqual(results['first_ts'], ts1.isoformat())
        self.assertEqual(results['last_ts'], ts2.isoformat())
        self.assertEqual(results['duration_sec'], 10.0)
        self.assertEqual(results['avg_pkt_size'], 125.0)
        self.assertAlmostEqual(results['avg_rate_bps'], (250*8)/10.0) # (250B * 8 bits/B) / 10s
        self.assertEqual(results['linktypes']['Ethernet'], 2)

    def test_ip_usage_collector(self):
        collector = IpUsageCollector()
        parsed_data_1 = {'ip': {'src_ip_bytes': socket.inet_aton("1.1.1.1"), 'dst_ip_bytes': socket.inet_aton("2.2.2.2"), 'version': 4, 'src_ip_str':'1.1.1.1', 'dst_ip_str':'2.2.2.2'}}
        parsed_data_2 = {'ip': {'src_ip_bytes': socket.inet_aton("1.1.1.1"), 'dst_ip_bytes': socket.inet_aton("3.3.3.3"), 'version': 4, 'src_ip_str':'1.1.1.1', 'dst_ip_str':'3.3.3.3'}}

        collector.process_packet(parsed_data_1)
        collector.process_packet(parsed_data_2)

        results = collector.get_results(top_n=1)
        self.assertEqual(results['top_src_ips'], [("1.1.1.1", 2)])
        self.assertEqual(len(results['top_dst_ips']), 1) # Could be 2.2.2.2 or 3.3.3.3

    # More tests would be needed for ConversationTracker, DnsAnalyzer, HttpAnalyzer, TlsAnalyzer, ReportGenerator
    # These would follow a similar pattern:
    # 1. Instantiate analyzer/generator
    # 2. Create mock parsed_data (for analyzers) or mock results (for ReportGenerator)
    # 3. Call process_packet or generation methods
    # 4. Assert results or mock calls (e.g., to _write_csv or print)

    @patch('report_generator.ReportGenerator._write_csv')
    @patch('builtins.print') # To suppress console summary during this test
    def test_report_generator_csv_calls(self, mock_print, mock_write_csv):
        args = argparse.Namespace(output_dir="test_out", ip_top_n=5, dns_top_n=5, http_top_n=5, tls_top_n=5, conv_top_n=5, verbose=False)
        report_gen = ReportGenerator(args)

        # Create a dummy all_results structure
        all_results = {
            'summary_stats': {'total_packets': 10},
            'proto_dist': {'ip_versions': {'IPv4': 10}},
            'ip_usage': {'top_src_ips': [('1.1.1.1', 5)], 'top_dst_ips': [('2.2.2.2', 5)]},
            'conversations': [{'ip1_s': '1.1.1.1', 'port1': 123, 'ip2_s': '2.2.2.2', 'port2': 80, 'proto': 6,
                               'pkts12':1,'bytes12':100,'pkts21':0,'bytes21':0,'first_ts':datetime.datetime.now(datetime.timezone.utc),
                               'last_ts':datetime.datetime.now(datetime.timezone.utc),'duration_s':0,'tcp_flags':None,
                               'total_pkts':1, 'total_bytes':100}],
            'dns_analysis': {'query_log': [{'ts':datetime.datetime.now(datetime.timezone.utc),'id':1,'name':'a.com','qtype':1}], 'top_queries': [('a.com',1)]},
            'http_analysis': {'requests': [{'ts':datetime.datetime.now(datetime.timezone.utc),'src_ip':'1.1.1.1','dst_ip':'2.2.2.2','method':'GET','host':'h.com','uri':'/','ua':'ua','ver':'1.1'}], 'top_hosts': [('h.com',1)]},
            'tls_analysis': {'client_hellos_sni': [{'ts':datetime.datetime.now(datetime.timezone.utc),'src':'1.1.1.1','dst':'2.2.2.2','sni':'s.com'}], 'top_sni': [('s.com',1)]}
        }

        report_gen.generate_csv_outputs(all_results)

        # Check if _write_csv was called for a few key files
        # Get all calls to mock_write_csv
        calls = mock_write_csv.call_args_list

        # Example: Check if 'summary_stats.csv' was called
        self.assertTrue(any(call[0][0] == "summary_stats.csv" for call in calls))
        self.assertTrue(any(call[0][0] == "conversations.csv" for call in calls))
        self.assertTrue(any(call[0][0] == "dns_queries.csv" for call in calls))
        # Add more checks as needed for other CSVs


if __name__ == '__main__':
    unittest.main()
