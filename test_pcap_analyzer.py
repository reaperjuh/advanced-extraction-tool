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
# These helpers build byte strings for different packet layers using dpkt
def _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP, payload=b'',
                      src_mac=b'\x00\x01\x02\x03\x04\x05',
                      dst_mac=b'\x06\x07\x08\x09\x0a\x0b'):
    eth = dpkt.ethernet.Ethernet(src=src_mac, dst=dst_mac, type=eth_type, data=payload)
    return bytes(eth)

def _build_ipv4_packet_obj(payload=b'', proto=dpkt.ip.IP_PROTO_TCP,
                        src_ip_str='192.168.1.10', dst_ip_str='192.168.1.20'):
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip_str),
        dst=socket.inet_aton(dst_ip_str),
        p=proto,
        data=payload,
        v=4 # Ensure version is set
    )
    ip.len = len(ip) # dpkt calculates this based on header + data
    return ip

def _build_ipv6_packet_obj(payload=b'', proto=dpkt.ip.IP_PROTO_TCP,
                        src_ip_str='::1', dst_ip_str='::2'):
    ip6 = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, src_ip_str),
        dst=socket.inet_pton(socket.AF_INET6, dst_ip_str),
        nxt=proto,  # nxt is the next header field in IPv6
        data=payload
    )
    ip6.plen = len(ip6.data) # Payload length
    return ip6

# Transport Layer Helper Objects
def _build_tcp_segment_obj(sport=12345, dport=80, flags=dpkt.tcp.TH_SYN, seq=1000, ack=0, data=b'TCP Payload'):
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        seq=seq,
        ack=ack,
        data=data
    )
    return tcp

def _build_udp_datagram_obj(sport=5353, dport=53, data=b'UDP Payload'):
    udp = dpkt.udp.UDP(
        sport=sport,
        dport=dport,
        data=data
    )
    udp.ulen = len(udp) # dpkt requires ulen to be set for UDP
    return udp

def _build_icmp_packet_obj(type=dpkt.icmp.ICMP_ECHO, code=0, data_payload=b'ICMP Payload'):
    # For ICMP_ECHO, data should be ICMP.Echo object
    if type == dpkt.icmp.ICMP_ECHO or type == dpkt.icmp.ICMP_ECHOREPLY:
        echo_payload = dpkt.icmp.ICMP.Echo(id=12345, seq=1, data=data_payload)
        icmp = dpkt.icmp.ICMP(type=type, code=code, data=echo_payload)
    else: # For other types, data can be simpler
        icmp = dpkt.icmp.ICMP(type=type, code=code, data=data_payload) # This might need adjustment based on specific type
    return icmp

def _build_icmpv6_packet_obj(type=dpkt.icmp6.ICMP6_ECHO_REQUEST, code=0, data_payload=b'ICMPv6 Payload'):
    if type == dpkt.icmp6.ICMP6_ECHO_REQUEST or type == dpkt.icmp6.ICMP6_ECHO_REPLY:
        echo_payload = dpkt.icmp6.ICMP6.Echo(id=54321, seq=1, data=data_payload)
        icmp6 = dpkt.icmp6.ICMP6(type=type, code=code, data=echo_payload)
    else:
        icmp6 = dpkt.icmp6.ICMP6(type=type, code=code, data=data_payload) # Adjust as needed
    return icmp6


class TestPcapAnalyzer(unittest.TestCase):
    def setUp(self):
        # Instantiate PacketParser for use in multiple tests
        self.packet_parser = PacketParser()

    def test_format_mac(self):
        self.assertEqual(format_mac(b'\x00\x11\x22\x33\x44\x55'), "00:11:22:33:44:55")

    def test_setup_parser(self):
        parser = setup_parser()
        args = parser.parse_args(["test.pcap", "--ip-top-n", "5"])
        self.assertEqual(args.pcap_file, "test.pcap")
        self.assertEqual(args.ip_top_n, 5)
        args_defaults = parser.parse_args(["test.pcap"])
        self.assertEqual(args_defaults.ip_top_n, 10)

    @patch('builtins.open', new_callable=mock_open)
    def test_pcap_reader_pcap(self, mock_file_open):
        mock_pcap_reader_instance = MagicMock(spec=dpkt.pcap.Reader)
        mock_pcap_reader_instance.datalink.return_value = dpkt.pcap.DLT_EN10MB
        mock_pcap_reader_instance.__iter__.return_value = iter([(1.0, b'data1')])

        # Mock the pcapng reader to fail, forcing fallback to pcap.Reader
        with patch('dpkt.pcapng.Reader', side_effect=ValueError("Not pcapng")), \
             patch('dpkt.pcap.Reader', return_value=mock_pcap_reader_instance):
            reader = PcapReader("dummy.pcap", verbose=False)
            packets = list(reader)
            reader.close()

        self.assertFalse(reader.is_pcapng)
        self.assertEqual(reader.linktype, dpkt.pcap.DLT_EN10MB)
        self.assertEqual(len(packets), 1)
        mock_file_open.assert_any_call("dummy.pcap", 'rb') # open for pcapng, then for pcap
        # Check that the file handle used by the reader (which is mock_file_open.return_value) was closed
        mock_file_open.return_value.close.assert_called_once()


    def test_parse_eth_ipv4_frame(self):
        src_mac_bytes = b'\x00\x01\x02\x03\x04\x05'
        dst_mac_bytes = b'\x06\x07\x08\x09\x0a\x0b'
        src_ip_str = '192.168.1.10'; dst_ip_str = '192.168.1.20'
        tcp_payload = b'TCP Segment'

        ipv4_obj = _build_ipv4_packet_obj(payload=tcp_payload, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str, proto=dpkt.ip.IP_PROTO_TCP)
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP, payload=bytes(ipv4_obj), src_mac=src_mac_bytes, dst_mac=dst_mac_bytes)

        parsed_data = self.packet_parser.parse_packet(1.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertEqual(parsed_data['linktype_str'], 'Ethernet')
        self.assertIsNotNone(parsed_data['eth'])
        self.assertEqual(parsed_data['eth']['src_mac'], format_mac(src_mac_bytes))
        self.assertEqual(parsed_data['eth']['dst_mac'], format_mac(dst_mac_bytes))
        self.assertEqual(parsed_data['eth']['type'], dpkt.ethernet.ETH_TYPE_IP)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 4)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        # self.assertEqual(parsed_data['payload'], tcp_payload) # Payload is now in transport.payload
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'TCP')
        self.assertEqual(parsed_data['payload'], tcp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_eth_ipv6_frame(self):
        src_mac_bytes = b'\x10\x11\x12\x13\x14\x15'
        dst_mac_bytes = b'\x16\x17\x18\x19\x1a\x1b'
        src_ip_str = '2001:db8::1'; dst_ip_str = '2001:db8::2'
        udp_payload = b'UDP Segment'

        # Create UDP packet first for IPv6 payload
        udp_obj = dpkt.udp.UDP(sport=54321, dport=53, data=udp_payload)
        udp_obj.ulen = len(udp_obj)

        ipv6_obj = _build_ipv6_packet_obj(payload=bytes(udp_obj), src_ip_str=src_ip_str, dst_ip_str=dst_ip_str, proto=dpkt.ip.IP_PROTO_UDP)
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP6, payload=bytes(ipv6_obj), src_mac=src_mac_bytes, dst_mac=dst_mac_bytes) # Corrected constant

        parsed_data = self.packet_parser.parse_packet(2.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertEqual(parsed_data['linktype_str'], 'Ethernet')
        self.assertIsNotNone(parsed_data['eth'])
        self.assertEqual(parsed_data['eth']['type'], dpkt.ethernet.ETH_TYPE_IP6) # Corrected constant

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 6)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_UDP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'UDP')
        self.assertEqual(parsed_data['payload'], udp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_eth_arp_frame(self):
        src_mac_bytes = b'\x20\x21\x22\x23\x24\x25'
        dst_mac_bytes = b'\x26\x27\x28\x29\x2a\x2b' # Typically broadcast for ARP request: ff:ff:ff:ff:ff:ff
        src_ip_str = '192.168.1.100'; target_ip_str = '192.168.1.1'

        arp_obj = dpkt.arp.ARP(
            sha=src_mac_bytes, spa=socket.inet_aton(src_ip_str),
            tha=b'\x00\x00\x00\x00\x00\x00', tpa=socket.inet_aton(target_ip_str), # Target MAC is unknown in request
            op=dpkt.arp.ARP_OP_REQUEST
        )
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_ARP, payload=bytes(arp_obj), src_mac=src_mac_bytes, dst_mac=dst_mac_bytes)

        parsed_data = self.packet_parser.parse_packet(3.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertEqual(parsed_data['linktype_str'], 'Ethernet')
        self.assertIsNotNone(parsed_data['eth'])
        self.assertEqual(parsed_data['eth']['type'], dpkt.ethernet.ETH_TYPE_ARP)
        self.assertIsNotNone(parsed_data['arp'])
        self.assertEqual(parsed_data['arp']['src_hw_addr_str'], format_mac(src_mac_bytes))
        self.assertEqual(parsed_data['arp']['src_proto_addr_str'], src_ip_str)
        self.assertEqual(parsed_data['arp']['op_str'], 'REQUEST')
        self.assertIsNone(parsed_data['ip']) # ARP is not IP
        self.assertIsNone(parsed_data['error'])


    # Test for SummaryStatsCollector (basic)
    def test_summary_stats_collector(self):
        collector = SummaryStatsCollector()
        ts1 = datetime.datetime(2023,1,1,10,0,0, tzinfo=datetime.timezone.utc)
        ts2 = datetime.datetime(2023,1,1,10,0,10, tzinfo=datetime.timezone.utc)
        collector.process_packet(ts1, 100, "Ethernet")
        collector.process_packet(ts2, 150, "Ethernet")
        results = collector.get_results()
        self.assertEqual(results['total_packets'], 2)

    # Test for IpUsageCollector (basic)
    def test_ip_usage_collector(self):
        collector = IpUsageCollector()
        parsed_data_1 = {'ip': {'version':4, 'src_ip_bytes': socket.inet_aton("1.1.1.1"), 'dst_ip_bytes': socket.inet_aton("2.2.2.2"), 'src_ip_str':'1.1.1.1', 'dst_ip_str':'2.2.2.2'}}
        collector.process_packet(parsed_data_1)
        results = collector.get_results(top_n=1)
        self.assertEqual(results['top_src_ips'], [("1.1.1.1", 1)])

    # Test for ReportGenerator (basic call check)
    @patch('pcap_analyzer.ReportGenerator._write_csv') # Note: patching where it's used
    @patch('builtins.print')
    def test_internal_report_generator_csv_calls(self, mock_print, mock_write_csv):
        args = argparse.Namespace(output_dir="test_out", ip_top_n=1, dns_top_n=1, http_top_n=1, tls_top_n=1, conv_top_n=1, verbose=False)
        report_gen = ReportGenerator(args)
        all_results = { # Simplified dummy data
            'summary_stats': {}, 'proto_dist': {}, 'ip_usage': {'top_src_ips':[],'top_dst_ips':[]},
            'conversations': [], 'dns_analysis': {'query_log':[],'top_queries':[]},
            'http_analysis': {'requests':[],'top_hosts':[]}, 'tls_analysis': {'client_hellos_sni':[],'top_sni':[]}
        }
        report_gen.generate_csv_outputs(all_results)
        self.assertTrue(mock_write_csv.called)
        self.assertTrue(any(call[0][0] == "summary_stats.csv" for call in mock_write_csv.call_args_list))

    # --- Tests for SLL (Linux Cooked Capture), NULL/Loopback, and Raw IP linktypes ---

    def test_parse_linux_sll_ipv4_packet(self):
        src_ip_str = '10.0.0.1'; dst_ip_str = '10.0.0.2'
        tcp_payload = b'SLL IPv4 TCP Payload'
        ipv4_obj = _build_ipv4_packet_obj(payload=tcp_payload, proto=dpkt.ip.IP_PROTO_TCP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        ipv4_bytes = bytes(ipv4_obj)

        # dpkt.sll.SLL.type corresponds to Ethernet protocol numbers
        sll_frame = dpkt.sll.SLL(type=dpkt.ethernet.ETH_TYPE_IP, data=ipv4_bytes)
        # Example SLL header fields - actual values might vary or not be checked deeply by parser initially
        sll_frame.hatype = dpkt.sll.ARPHRD_LOOPBACK
        sll_frame.pkttype = dpkt.sll.PACKET_HOST
        sll_frame.halen = 0
        sll_frame.addr = b''
        sll_frame_bytes = bytes(sll_frame)

        parsed_data = self.packet_parser.parse_packet(4.0, sll_frame_bytes, dpkt.pcap.DLT_LINUX_SLL)

        self.assertEqual(parsed_data['linktype_str'], 'Linux SLL')
        # Assuming PacketParser will store sll header info if it parses it
        # For now, the main goal is IP extraction. Detailed SLL field check can be added if parser supports it.
        # self.assertIsNotNone(parsed_data.get('sll'))
        # if parsed_data.get('sll'):
        #     self.assertEqual(parsed_data['sll']['type'], dpkt.ethernet.ETH_TYPE_IP)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 4)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'TCP')
        self.assertEqual(parsed_data['payload'], tcp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_linux_sll_ipv6_packet(self):
        src_ip_str = '2001:db8::aa'; dst_ip_str = '2001:db8::bb'
        udp_payload = b'SLL IPv6 UDP Payload'
        ipv6_obj = _build_ipv6_packet_obj(payload=udp_payload, proto=dpkt.ip.IP_PROTO_UDP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        ipv6_bytes = bytes(ipv6_obj)

        sll_frame = dpkt.sll.SLL(type=dpkt.ethernet.ETH_TYPE_IP6, data=ipv6_bytes) # Correct type for IPv6
        sll_frame_bytes = bytes(sll_frame)

        parsed_data = self.packet_parser.parse_packet(5.0, sll_frame_bytes, dpkt.pcap.DLT_LINUX_SLL)

        self.assertEqual(parsed_data['linktype_str'], 'Linux SLL')
        # self.assertIsNotNone(parsed_data.get('sll'))

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 6)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_UDP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'UDP')
        self.assertEqual(parsed_data['payload'], udp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_null_loopback_ipv4_packet(self):
        src_ip_str = '127.0.0.1'; dst_ip_str = '127.0.0.1'
        icmp_payload_data = b'\x08\x00\x01\x02\x03\x04' # Example ICMP Echo request
        icmp_payload = dpkt.icmp.ICMP.Echo(id=0x1234, seq=1, data=icmp_payload_data)

        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(icmp_payload), proto=dpkt.ip.IP_PROTO_ICMP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        ipv4_bytes = bytes(ipv4_obj)

        # dpkt.loopback.Loopback is used for DLT_NULL and DLT_LOOP
        # The family field indicates the protocol (AF_INET for IPv4, AF_INET6 for IPv6)
        loopback_frame = dpkt.loopback.Loopback(family=socket.AF_INET, data=ipv4_bytes)
        loopback_frame_bytes = bytes(loopback_frame)

        parsed_data = self.packet_parser.parse_packet(6.0, loopback_frame_bytes, dpkt.pcap.DLT_NULL)

        self.assertEqual(parsed_data['linktype_str'], 'Loopback/Null(0)') # Actual string from parser
        # self.assertIsNotNone(parsed_data.get('loopback'))
        # if parsed_data.get('loopback'):
        #    self.assertEqual(parsed_data['loopback']['family'], socket.AF_INET)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 4)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_ICMP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'ICMP')
        self.assertEqual(parsed_data['payload'], icmp_payload_data) # ICMP.data.data
        self.assertIsNone(parsed_data['error'])

    def test_parse_null_loopback_ipv6_packet(self):
        src_ip_str = '::1'; dst_ip_str = '::1'
        tcp_payload = b'Loopback IPv6 TCP Payload'
        ipv6_obj = _build_ipv6_packet_obj(payload=tcp_payload, proto=dpkt.ip.IP_PROTO_TCP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        ipv6_bytes = bytes(ipv6_obj)

        loopback_frame = dpkt.loopback.Loopback(family=socket.AF_INET6, data=ipv6_bytes)
        loopback_frame_bytes = bytes(loopback_frame)

        parsed_data = self.packet_parser.parse_packet(6.5, loopback_frame_bytes, dpkt.pcap.DLT_NULL) # Can also test DLT_LOOP

        self.assertEqual(parsed_data['linktype_str'], 'Loopback/Null(0)') # Actual string from parser
        # self.assertIsNotNone(parsed_data.get('loopback'))

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 6)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'TCP')
        self.assertEqual(parsed_data['payload'], tcp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_raw_ip_ipv4_packet(self):
        src_ip_str = '172.16.0.1'; dst_ip_str = '172.16.0.2'
        raw_payload = b'Raw IPv4 Payload'
        # For DLT_RAW, the buffer is directly the IP packet
        ipv4_obj = _build_ipv4_packet_obj(payload=raw_payload, proto=dpkt.ip.IP_PROTO_UDP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        # Construct a UDP object to make the payload meaningful for the parser's transport layer
        udp_obj = dpkt.udp.UDP(sport=1234, dport=5678, data=raw_payload)
        udp_obj.ulen = len(udp_obj)
        ipv4_obj.data = bytes(udp_obj)
        ipv4_obj.len = len(ipv4_obj) # Recalculate length
        ipv4_bytes = bytes(ipv4_obj)


        parsed_data = self.packet_parser.parse_packet(7.0, ipv4_bytes, dpkt.pcap.DLT_RAW)

        self.assertEqual(parsed_data['linktype_str'], 'Raw IPv4') # As per current parser logic for DLT_RAW
        self.assertIsNone(parsed_data.get('eth'))
        self.assertIsNone(parsed_data.get('sll'))
        self.assertIsNone(parsed_data.get('loopback'))

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 4)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_UDP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'UDP')
        self.assertEqual(parsed_data['payload'], raw_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_raw_ip_ipv6_packet(self):
        src_ip_str = 'fd00::a'; dst_ip_str = 'fd00::b'
        raw_payload = b'Raw IPv6 Payload'
        ipv6_obj = _build_ipv6_packet_obj(payload=raw_payload, proto=dpkt.ip.IP_PROTO_TCP, src_ip_str=src_ip_str, dst_ip_str=dst_ip_str)
        tcp_obj = dpkt.tcp.TCP(sport=1234, dport=80, data=raw_payload)
        ipv6_obj.data = bytes(tcp_obj)
        ipv6_obj.plen = len(ipv6_obj.data) # Recalculate payload length
        ipv6_bytes = bytes(ipv6_obj)

        parsed_data = self.packet_parser.parse_packet(8.0, ipv6_bytes, dpkt.pcap.DLT_RAW)

        self.assertEqual(parsed_data['linktype_str'], 'Raw IPv6') # As per current parser logic
        self.assertIsNone(parsed_data.get('eth'))

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 6)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'TCP')
        self.assertEqual(parsed_data['payload'], raw_payload)
        self.assertIsNone(parsed_data['error'])

    # --- Tests for Transport Layer Parsing (TCP, UDP, ICMP, ICMPv6) ---

    def test_parse_ip_tcp_packet(self):
        # IPv4 TCP
        tcp_payload_v4 = b'Hello IPv4 TCP'
        tcp_obj_v4 = _build_tcp_segment_obj(sport=10001, dport=443, flags=(dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), data=tcp_payload_v4)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(tcp_obj_v4), proto=dpkt.ip.IP_PROTO_TCP, src_ip_str="1.2.3.4", dst_ip_str="5.6.7.8")
        eth_frame_bytes_v4 = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data_v4 = self.packet_parser.parse_packet(10.0, eth_frame_bytes_v4, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data_v4['ip'], "IPv4 object should be parsed")
        self.assertEqual(parsed_data_v4['ip']['src_ip_str'], "1.2.3.4")
        self.assertIsNotNone(parsed_data_v4['transport'], "Transport field should be populated for IPv4 TCP")
        self.assertEqual(parsed_data_v4['transport']['type'], 'TCP')
        self.assertEqual(parsed_data_v4['transport']['src_port'], 10001)
        self.assertEqual(parsed_data_v4['transport']['dst_port'], 443)
        self.assertEqual(parsed_data_v4['transport']['flags'], (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))
        self.assertIsInstance(parsed_data_v4['transport_obj'], dpkt.tcp.TCP)
        self.assertEqual(parsed_data_v4['payload'], tcp_payload_v4)
        self.assertIsNone(parsed_data_v4['error'])

        # IPv6 TCP
        tcp_payload_v6 = b'Hello IPv6 TCP'
        tcp_obj_v6 = _build_tcp_segment_obj(sport=10002, dport=80, flags=dpkt.tcp.TH_FIN, data=tcp_payload_v6)
        ipv6_obj = _build_ipv6_packet_obj(payload=bytes(tcp_obj_v6), proto=dpkt.ip.IP_PROTO_TCP, src_ip_str="2001:db8::a", dst_ip_str="2001:db8::b")
        eth_frame_bytes_v6 = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP6, payload=bytes(ipv6_obj))

        parsed_data_v6 = self.packet_parser.parse_packet(10.1, eth_frame_bytes_v6, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data_v6['ip'], "IPv6 object should be parsed")
        self.assertEqual(parsed_data_v6['ip']['src_ip_str'], "2001:db8::a")
        self.assertIsNotNone(parsed_data_v6['transport'], "Transport field should be populated for IPv6 TCP")
        self.assertEqual(parsed_data_v6['transport']['type'], 'TCP')
        self.assertEqual(parsed_data_v6['transport']['src_port'], 10002)
        self.assertEqual(parsed_data_v6['transport']['dst_port'], 80)
        self.assertEqual(parsed_data_v6['transport']['flags'], dpkt.tcp.TH_FIN)
        self.assertIsInstance(parsed_data_v6['transport_obj'], dpkt.tcp.TCP)
        self.assertEqual(parsed_data_v6['payload'], tcp_payload_v6)
        self.assertIsNone(parsed_data_v6['error'])

    def test_parse_ip_udp_packet(self):
        # IPv4 UDP
        udp_payload_v4 = b'DNS Query via IPv4'
        udp_obj_v4 = _build_udp_datagram_obj(sport=53001, dport=53, data=udp_payload_v4)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(udp_obj_v4), proto=dpkt.ip.IP_PROTO_UDP, src_ip_str="10.0.0.3", dst_ip_str="10.0.0.4")
        eth_frame_bytes_v4 = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data_v4 = self.packet_parser.parse_packet(11.0, eth_frame_bytes_v4, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data_v4['ip'])
        self.assertEqual(parsed_data_v4['ip']['src_ip_str'], "10.0.0.3")
        self.assertIsNotNone(parsed_data_v4['transport'])
        self.assertEqual(parsed_data_v4['transport']['type'], 'UDP')
        self.assertEqual(parsed_data_v4['transport']['src_port'], 53001)
        self.assertEqual(parsed_data_v4['transport']['dst_port'], 53)
        self.assertIsInstance(parsed_data_v4['transport_obj'], dpkt.udp.UDP)
        self.assertEqual(parsed_data_v4['payload'], udp_payload_v4)
        self.assertIsNone(parsed_data_v4['error'])

        # IPv6 UDP
        udp_payload_v6 = b'NTP via IPv6'
        udp_obj_v6 = _build_udp_datagram_obj(sport=123, dport=123, data=udp_payload_v6)
        ipv6_obj = _build_ipv6_packet_obj(payload=bytes(udp_obj_v6), proto=dpkt.ip.IP_PROTO_UDP, src_ip_str="2001:db8::c", dst_ip_str="2001:db8::d")
        eth_frame_bytes_v6 = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP6, payload=bytes(ipv6_obj))

        parsed_data_v6 = self.packet_parser.parse_packet(11.1, eth_frame_bytes_v6, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data_v6['ip'])
        self.assertEqual(parsed_data_v6['ip']['src_ip_str'], "2001:db8::c")
        self.assertIsNotNone(parsed_data_v6['transport'])
        self.assertEqual(parsed_data_v6['transport']['type'], 'UDP')
        self.assertEqual(parsed_data_v6['transport']['src_port'], 123)
        self.assertEqual(parsed_data_v6['transport']['dst_port'], 123)
        self.assertIsInstance(parsed_data_v6['transport_obj'], dpkt.udp.UDP)
        self.assertEqual(parsed_data_v6['payload'], udp_payload_v6)
        self.assertIsNone(parsed_data_v6['error'])

    def test_parse_ip_icmp_packet(self):
        icmp_payload = b'Ping Reply IPv4'
        icmp_obj = _build_icmp_packet_obj(type=dpkt.icmp.ICMP_ECHOREPLY, code=0, data_payload=icmp_payload)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(icmp_obj), proto=dpkt.ip.IP_PROTO_ICMP, src_ip_str="8.8.8.8", dst_ip_str="192.168.0.100")
        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data = self.packet_parser.parse_packet(12.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['src_ip_str'], "8.8.8.8")
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'ICMP')
        self.assertEqual(parsed_data['transport']['icmp_type'], dpkt.icmp.ICMP_ECHOREPLY)
        self.assertEqual(parsed_data['transport']['icmp_code'], 0)
        self.assertIsInstance(parsed_data['transport_obj'], dpkt.icmp.ICMP)
        self.assertEqual(parsed_data['payload'], icmp_payload) # Handled by getattr in parser
        self.assertIsNone(parsed_data['error'])

    def test_parse_ip_icmpv6_packet(self):
        icmpv6_payload = b'Echo Reply IPv6'
        icmpv6_obj = _build_icmpv6_packet_obj(type=dpkt.icmp6.ICMP6_ECHO_REPLY, code=0, data_payload=icmpv6_payload)
        ipv6_obj = _build_ipv6_packet_obj(payload=bytes(icmpv6_obj), proto=dpkt.ip.IP_PROTO_ICMPV6, src_ip_str="2001:4860:4860::8888", dst_ip_str="2001:db8::e")
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP6, payload=bytes(ipv6_obj))

        parsed_data = self.packet_parser.parse_packet(13.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['src_ip_str'], "2001:4860:4860::8888")
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'ICMPv6')
        self.assertEqual(parsed_data['transport']['icmp_type'], dpkt.icmp6.ICMP6_ECHO_REPLY)
        self.assertEqual(parsed_data['transport']['icmp_code'], 0)
        self.assertIsInstance(parsed_data['transport_obj'], dpkt.icmp6.ICMP6)
        self.assertEqual(parsed_data['payload'], icmpv6_payload) # Handled by getattr in parser
        self.assertIsNone(parsed_data['error'])

    # --- Tests for Application Layer Parsing (DNS, HTTP, TLS) ---

    def _build_dns_query_payload(self, qname='example.com', qtype=dpkt.dns.DNS_A, qid=123):
        dns_req = dpkt.dns.DNS(id=qid, qd=[dpkt.dns.DNS.Q(name=qname, type=qtype)])
        return bytes(dns_req)

    def _build_http_request_payload(self, method='GET', uri='/index.html', headers=None, body=b''):
        if headers is None:
            headers = {'Host': 'example.com', 'User-Agent': 'TestClient/1.0'}
        http_req = dpkt.http.Request(method=method, uri=uri, headers=headers, body=body)
        return bytes(http_req)

    def _build_tls_client_hello_payload(self, server_name='sni.example.com'):
        # Simplified Client Hello with SNI
        # This is a basic construction. Real Client Hellos are more complex.
        # dpkt.ssl.TLSClientHello's constructor is not straightforward for direct use with all fields.
        # We build it up from components.

        # SNI Extension
        sni_ext = dpkt.ssl.TLSExtension(
            type=dpkt.ssl.TLSEXT_SERVER_NAME,
            data=dpkt.ssl.TLSServerName(
                # ServerName list can contain multiple names, we use one
                # Each name is TLSServerNameEntry(type=0 for host_name, name=b'sni.example.com')
                # For simplicity, directly encode the server name list part of the extension data:
                # list_len (2 bytes), type (1 byte, 0=host_name), name_len (2 bytes), name (variable)
                data= (len(server_name) + 3).to_bytes(2, 'big') + \
                      b'\x00' + \
                      len(server_name).to_bytes(2, 'big') + \
                      server_name.encode('utf-8')
            )
        )

        client_hello = dpkt.ssl.TLSClientHello(
            version=dpkt.ssl.TLS_V1_2, # or SSL3_V, TLS_V1 etc.
            random=os.urandom(32),
            session_id=b'',
            cipher_suites=[dpkt.ssl.TLS_RSA_WITH_AES_128_CBC_SHA], # Example cipher
            comp_methods=[dpkt.ssl.TLS_COMP_NULL],
            extensions=[sni_ext]
        )

        handshake = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_CLIENT_HELLO, data=client_hello)
        # A TLS record can contain multiple handshake messages, but for Client Hello it's typically one.
        # For simplicity, we'll wrap this single handshake message.
        # dpkt.ssl.TLS expects its data to be a list of records or a single record.
        # A record is dpkt.ssl.TLSRecord (type, version, data=handshake_bytes)
        # However, PacketParser directly tries to parse tcp.data as dpkt.ssl.TLS which expects the record wrapper.
        # So, we create a TLSRecord containing the Handshake.

        tls_record = dpkt.ssl.TLSRecord(
            type=dpkt.ssl.TLS_HANDSHAKE, # Content type: Handshake
            version=dpkt.ssl.TLS_V1, # Record layer version (can be different from CH version)
            data=bytes(handshake)
        )
        return bytes(tls_record)


    def test_parse_app_layer_dns(self):
        q_name = 'test.dnspy.org'
        q_id = 777
        dns_payload_bytes = self._build_dns_query_payload(qname=q_name, qid=q_id)
        udp_obj = _build_udp_datagram_obj(sport=10003, dport=53, data=dns_payload_bytes)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(udp_obj), proto=dpkt.ip.IP_PROTO_UDP)
        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data = self.packet_parser.parse_packet(20.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data.get('app_layer'), "App layer should be populated for DNS")
        self.assertEqual(parsed_data['app_layer']['type'], 'DNS')
        self.assertIsInstance(parsed_data['app_layer']['data_obj'], dpkt.dns.DNS)
        self.assertEqual(parsed_data['app_layer']['data_obj'].id, q_id)
        self.assertTrue(len(parsed_data['app_layer']['data_obj'].qd) > 0, "DNS queries should exist")
        self.assertEqual(parsed_data['app_layer']['data_obj'].qd[0].name, q_name)
        # dpkt.dns.DNS consumes the payload, so transport payload should be empty
        self.assertEqual(parsed_data['payload'], b'', "Payload should be empty after DNS parsing")
        self.assertIsNone(parsed_data['error'])

    def test_parse_app_layer_http_request(self):
        http_req_payload_bytes = self._build_http_request_payload(method='POST', uri='/submit', headers={'Host': 'myhost.com', 'Content-Type':'text/plain'}, body=b'data')
        tcp_obj = _build_tcp_segment_obj(sport=10004, dport=80, data=http_req_payload_bytes)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(tcp_obj), proto=dpkt.ip.IP_PROTO_TCP)
        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data = self.packet_parser.parse_packet(21.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data.get('app_layer'), "App layer should be populated for HTTP")
        self.assertEqual(parsed_data['app_layer']['type'], 'HTTP')
        self.assertIsInstance(parsed_data['app_layer']['data_obj'], dpkt.http.Request)
        self.assertEqual(parsed_data['app_layer']['data_obj'].method, 'POST')
        self.assertEqual(parsed_data['app_layer']['data_obj'].uri, '/submit')
        self.assertEqual(parsed_data['app_layer']['data_obj'].headers['host'], 'myhost.com')
        self.assertEqual(parsed_data['app_layer']['data_obj'].body, b'data')
        # dpkt.http.Request consumes the payload
        self.assertEqual(parsed_data['payload'], b'', "Payload should be empty after HTTP parsing")
        self.assertIsNone(parsed_data['error'])

    def test_parse_app_layer_tls_client_hello_sni(self):
        server_name_to_test = 'sni.example.com'
        tls_payload_bytes = self._build_tls_client_hello_payload(server_name=server_name_to_test)

        tcp_obj = _build_tcp_segment_obj(sport=10005, dport=443, data=tls_payload_bytes)
        ipv4_obj = _build_ipv4_packet_obj(payload=bytes(tcp_obj), proto=dpkt.ip.IP_PROTO_TCP)
        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))

        parsed_data = self.packet_parser.parse_packet(22.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data.get('app_layer'), "App layer should be populated for TLS")
        self.assertEqual(parsed_data['app_layer']['type'], 'TLS')
        self.assertIsInstance(parsed_data['app_layer']['data_obj'], dpkt.ssl.TLS)
        # dpkt.ssl.TLS object itself is the record layer. The handshake message is inside.
        # We are checking that the parser identified it as TLS and passed the dpkt.ssl.TLS object.
        # Deeper SNI parsing is done by TlsAnalyzer, not PacketParser itself.
        # The payload of the TCP segment is the TLS record bytes, so PacketParser.payload should be empty.
        self.assertEqual(parsed_data['payload'], b'', "Payload should be empty after TLS parsing")
        self.assertIsNone(parsed_data['error'])

    def test_parse_app_layer_non_standard_ports(self):
        # DNS-like payload on non-53 port
        dns_payload_bytes = self._build_dns_query_payload(qname='nonstandard.dns', qid=778)
        udp_obj_dns = _build_udp_datagram_obj(sport=53333, dport=53333, data=dns_payload_bytes) # Non-standard port
        ipv4_obj_dns = _build_ipv4_packet_obj(payload=bytes(udp_obj_dns), proto=dpkt.ip.IP_PROTO_UDP)
        eth_frame_dns = _build_eth_packet(payload=bytes(ipv4_obj_dns))
        parsed_data_dns = self.packet_parser.parse_packet(23.0, eth_frame_dns, dpkt.pcap.DLT_EN10MB)
        self.assertIsNone(parsed_data_dns.get('app_layer'), "App layer should be None for DNS on non-standard port")
        self.assertEqual(parsed_data_dns['payload'], dns_payload_bytes, "Payload should be original UDP data for non-standard DNS port")

        # HTTP-like payload on non-80 port
        http_req_payload_bytes = self._build_http_request_payload(uri='/nonstandard')
        tcp_obj_http = _build_tcp_segment_obj(sport=8080, dport=8080, data=http_req_payload_bytes) # Non-standard port
        ipv4_obj_http = _build_ipv4_packet_obj(payload=bytes(tcp_obj_http), proto=dpkt.ip.IP_PROTO_TCP)
        eth_frame_http = _build_eth_packet(payload=bytes(ipv4_obj_http))
        parsed_data_http = self.packet_parser.parse_packet(23.1, eth_frame_http, dpkt.pcap.DLT_EN10MB)
        self.assertIsNone(parsed_data_http.get('app_layer'), "App layer should be None for HTTP on non-standard port")
        self.assertEqual(parsed_data_http['payload'], http_req_payload_bytes, "Payload should be original TCP data for non-standard HTTP port")

        # TLS-like payload on non-443 port
        tls_payload_bytes = self._build_tls_client_hello_payload(server_name='nonstandard.sni')
        tcp_obj_tls = _build_tcp_segment_obj(sport=8443, dport=8443, data=tls_payload_bytes) # Non-standard port
        ipv4_obj_tls = _build_ipv4_packet_obj(payload=bytes(tcp_obj_tls), proto=dpkt.ip.IP_PROTO_TCP)
        eth_frame_tls = _build_eth_packet(payload=bytes(ipv4_obj_tls))
        parsed_data_tls = self.packet_parser.parse_packet(23.2, eth_frame_tls, dpkt.pcap.DLT_EN10MB)
        self.assertIsNone(parsed_data_tls.get('app_layer'), "App layer should be None for TLS on non-standard port")
        self.assertEqual(parsed_data_tls['payload'], tls_payload_bytes, "Payload should be original TCP data for non-standard TLS port")

    # --- Tests for Malformed Packet Error Handling ---

    def test_parse_malformed_ethernet_frame(self):
        # Ethernet frame too short (13 bytes) to contain EtherType
        malformed_eth_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08'
        parsed_data = self.packet_parser.parse_packet(30.0, malformed_eth_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['error'], "Error should be reported for malformed Ethernet")
        self.assertIn("Link Error", parsed_data['error']) # Parser sets "DPKT Link Error"
        self.assertIsNone(parsed_data['eth'])
        self.assertIsNone(parsed_data['ip'])
        self.assertIsNone(parsed_data['transport'])
        self.assertEqual(parsed_data['payload'], malformed_eth_bytes, "Payload should be original buffer on link error")

    def test_parse_malformed_ip_packet(self):
        # Malformed IP packet: version 3, which dpkt.ip.IP should reject or misinterpret.
        # Standard IP header is 20 bytes. This is a truncated one with version field manipulated.
        malformed_ip_payload = b'\x35\x00\x00\x10\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x0a' # Only 16 bytes, version 3
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP, payload=malformed_ip_payload)

        parsed_data = self.packet_parser.parse_packet(31.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['error'], "Error should be reported for malformed IP")
        # dpkt.ip.IP might raise UnpackError for short packet or error if version is not 4/6
        # The _parse_ip_packet helper might set its own error if version is not 4 or 6.
        # The parser's _parse_ip_packet also sets an error for unknown IP versions.
        self.assertTrue("short" in parsed_data['error'].lower() or "unknown ip version" in parsed_data['error'].lower() or "invalid ip object" in parsed_data['error'].lower(), f"Unexpected error message: {parsed_data['error']}")

        self.assertIsNone(parsed_data['ip']) # Or it might be partially filled depending on dpkt, but should not be fully valid
        self.assertIsNone(parsed_data['transport'])
        self.assertEqual(parsed_data['payload'], malformed_ip_payload, "Payload should be malformed IP segment")

    def test_parse_malformed_tcp_segment(self):
        # Malformed TCP: Data offset 1 (0x10 in header) which is too small (min 5 words / 20 bytes)
        malformed_tcp_payload = b'\xc0\x01\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x10\x02\x71\x10\x00\x00\x00\x00'
        ipv4_obj = _build_ipv4_packet_obj(payload=malformed_tcp_payload, proto=dpkt.ip.IP_PROTO_TCP)
        # Ensure IP object's data field is actually the malformed payload
        ipv4_obj.data = malformed_tcp_payload
        ipv4_obj.len = len(ipv4_obj) # Recalculate length

        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))
        parsed_data = self.packet_parser.parse_packet(32.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['ip'], "IP part should be parsed correctly")
        self.assertIsNotNone(parsed_data['error'], "Error should be reported for malformed TCP")
        # dpkt.tcp.TCP typically raises UnpackError for bad data offset
        self.assertTrue("transportparseerror" in parsed_data['error'].lower() and \
                        ("short" in parsed_data['error'].lower() or "offset" in parsed_data['error'].lower()),
                        f"Unexpected error for malformed TCP: {parsed_data['error']}")
        self.assertIsNone(parsed_data['transport'], "Transport field should be None or reflect error")
        self.assertEqual(parsed_data['payload'], malformed_tcp_payload, "Payload should be malformed TCP segment")

    def test_parse_malformed_udp_datagram(self):
        # Malformed UDP: Declared UDP length 0x000A (10 bytes), but IP payload provides less after UDP header (e.g. 1 byte data)
        # UDP header is 8 bytes. So, total 9 bytes.
        # dpkt.udp.UDP checks if len(data) < udp.ulen - UDP_HDR_LEN.
        # IP packet payload:
        malformed_udp_payload = b'\xc0\x02\x00\x35\x00\x0A\x00\x00Z' # sport, dport, ulen=10, sum, Z (1 byte data)
                                                                 # Total 9 bytes. ulen (10) > actual_payload_from_ip (9)
                                                                 # dpkt will try to read 10-8=2 bytes of data, but only 1 is available.

        # We need to ensure the IP packet's payload length is consistent with malformed_udp_payload
        ipv4_obj = _build_ipv4_packet_obj(payload=b'', proto=dpkt.ip.IP_PROTO_UDP) # Placeholder payload
        ipv4_obj.data = malformed_udp_payload # Set the actual malformed UDP
        ipv4_obj.len = len(ipv4_obj) # Recalculate length based on actual data

        eth_frame_bytes = _build_eth_packet(payload=bytes(ipv4_obj))
        parsed_data = self.packet_parser.parse_packet(33.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertIsNotNone(parsed_data['ip'], "IP part should be parsed correctly")
        self.assertIsNotNone(parsed_data['error'], "Error should be reported for malformed UDP")
        # dpkt.udp.UDP typically raises UnpackError if len(data) < udp.ulen - UDP_HDR_LEN
        self.assertTrue("transportparseerror" in parsed_data['error'].lower() and \
                        "short" in parsed_data['error'].lower(),
                        f"Unexpected error for malformed UDP: {parsed_data['error']}")
        self.assertIsNone(parsed_data['transport'], "Transport field should be None or reflect error")
        self.assertEqual(parsed_data['payload'], malformed_udp_payload, "Payload should be malformed UDP segment")


    # --- Tests for ConversationTracker ---
    def test_conversation_tracker_tcp_udp(self):
        tracker = ConversationTracker()

        # TCP Conversation 1 (Client -> Server, Server -> Client)
        ts1 = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        tcp_pkt1_data = {
            'timestamp': ts1,
            'ip': {'src_ip_bytes': socket.inet_aton('192.168.1.100'), 'dst_ip_bytes': socket.inet_aton('10.0.0.1'),
                   'src_ip_str': '192.168.1.100', 'dst_ip_str': '10.0.0.1', 'proto': dpkt.ip.IP_PROTO_TCP, 'len': 60},
            'transport': {'type': 'TCP', 'src_port': 12345, 'dst_port': 80, 'flags': dpkt.tcp.TH_SYN}
        }
        tracker.process_packet(tcp_pkt1_data)

        ts2 = ts1 + datetime.timedelta(seconds=1)
        tcp_pkt2_data = { # Response
            'timestamp': ts2,
            'ip': {'src_ip_bytes': socket.inet_aton('10.0.0.1'), 'dst_ip_bytes': socket.inet_aton('192.168.1.100'),
                   'src_ip_str': '10.0.0.1', 'dst_ip_str': '192.168.1.100', 'proto': dpkt.ip.IP_PROTO_TCP, 'len': 60},
            'transport': {'type': 'TCP', 'src_port': 80, 'dst_port': 12345, 'flags': dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK}
        }
        tracker.process_packet(tcp_pkt2_data)

        ts3 = ts2 + datetime.timedelta(seconds=1)
        tcp_pkt3_data = { # Client ACK + Data
            'timestamp': ts3,
            'ip': {'src_ip_bytes': socket.inet_aton('192.168.1.100'), 'dst_ip_bytes': socket.inet_aton('10.0.0.1'),
                   'src_ip_str': '192.168.1.100', 'dst_ip_str': '10.0.0.1', 'proto': dpkt.ip.IP_PROTO_TCP, 'len': 100}, # 40B data
            'transport': {'type': 'TCP', 'src_port': 12345, 'dst_port': 80, 'flags': dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH}
        }
        tracker.process_packet(tcp_pkt3_data)

        # UDP Conversation 2
        ts_udp1 = datetime.datetime(2023, 1, 1, 12, 0, 5, tzinfo=datetime.timezone.utc)
        udp_pkt1_data = {
            'timestamp': ts_udp1,
            'ip': {'src_ip_bytes': socket.inet_aton('192.168.1.200'), 'dst_ip_bytes': socket.inet_aton('10.0.0.2'),
                   'src_ip_str': '192.168.1.200', 'dst_ip_str': '10.0.0.2', 'proto': dpkt.ip.IP_PROTO_UDP, 'len': 78}, # 50B data
            'transport': {'type': 'UDP', 'src_port': 54321, 'dst_port': 53}
        }
        tracker.process_packet(udp_pkt1_data)

        results = tracker.get_results(top_n=None)
        self.assertEqual(len(results), 2, "Should have tracked 2 unique conversations")

        # Verify TCP Conversation
        tcp_conv = None
        for conv in results:
            if conv['proto'] == dpkt.ip.IP_PROTO_TCP:
                tcp_conv = conv
                break
        self.assertIsNotNone(tcp_conv, "TCP conversation not found in results")

        # Canonical key places smaller IP/port tuple first
        self.assertEqual(tcp_conv['ip1_s'], '10.0.0.1')
        self.assertEqual(tcp_conv['port1'], 80)
        self.assertEqual(tcp_conv['ip2_s'], '192.168.1.100')
        self.assertEqual(tcp_conv['port2'], 12345)

        self.assertEqual(tcp_conv['pkts12'], 1, "Packets from 10.0.0.1:80 to 192.168.1.100:12345") # Server to client
        self.assertEqual(tcp_conv['bytes12'], 60)
        self.assertEqual(tcp_conv['pkts21'], 2, "Packets from 192.168.1.100:12345 to 10.0.0.1:80") # Client to server
        self.assertEqual(tcp_conv['bytes21'], 60 + 100)

        self.assertEqual(tcp_conv['first_ts'], ts1)
        self.assertEqual(tcp_conv['last_ts'], ts3)
        self.assertAlmostEqual(tcp_conv['duration_s'], (ts3 - ts1).total_seconds())

        expected_tcp_flags = collections.Counter({'SYN': 2, 'ACK': 2, 'PSH':1}) # SYN from pkt1, SYN/ACK from pkt2, ACK/PSH from pkt3
        self.assertEqual(collections.Counter(tcp_conv['tcp_flags']), expected_tcp_flags)

        # Verify UDP Conversation
        udp_conv = None
        for conv in results:
            if conv['proto'] == dpkt.ip.IP_PROTO_UDP:
                udp_conv = conv
                break
        self.assertIsNotNone(udp_conv, "UDP conversation not found")
        self.assertEqual(udp_conv['ip1_s'], '10.0.0.2')
        self.assertEqual(udp_conv['port1'], 53)
        self.assertEqual(udp_conv['ip2_s'], '192.168.1.200')
        self.assertEqual(udp_conv['port2'], 54321)
        self.assertEqual(udp_conv['pkts21'], 1) # 192.168.1.200 -> 10.0.0.2
        self.assertEqual(udp_conv['bytes21'], 78)
        self.assertEqual(udp_conv['pkts12'], 0)
        self.assertIsNone(udp_conv['tcp_flags'])


    def test_conversation_tracker_non_tcp_udp(self):
        tracker = ConversationTracker()
        ts_icmp = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        # ICMP packet with IP layer
        mock_icmp_packet_data = {
            'timestamp': ts_icmp,
            'ip': {'src_ip_bytes': socket.inet_aton('1.1.1.1'), 'dst_ip_bytes': socket.inet_aton('2.2.2.2'),
                   'src_ip_str': '1.1.1.1', 'dst_ip_str': '2.2.2.2',
                   'proto': dpkt.ip.IP_PROTO_ICMP, 'len': 28},
            'transport': {'type': 'ICMP', 'icmp_type': 8, 'icmp_code': 0} # No ports for ICMP
        }
        tracker.process_packet(mock_icmp_packet_data)
        results = tracker.get_results()

        # As per current ConversationTracker logic, ICMP will create a conversation
        self.assertEqual(len(results), 1, "ICMP conversation should be tracked")
        icmp_conv = results[0]
        self.assertEqual(icmp_conv['proto'], dpkt.ip.IP_PROTO_ICMP)
        self.assertEqual(icmp_conv['ip1_s'], '1.1.1.1')
        self.assertEqual(icmp_conv['ip2_s'], '2.2.2.2')
        self.assertEqual(icmp_conv['port1'], 0) # Ports are 0 for non-TCP/UDP
        self.assertEqual(icmp_conv['port2'], 0)
        self.assertEqual(icmp_conv['pkts12'], 1) # 1.1.1.1 -> 2.2.2.2
        self.assertEqual(icmp_conv['bytes12'], 28)
        self.assertIsNone(icmp_conv['tcp_flags'])

        # Packet with no IP layer (should be ignored by ConversationTracker)
        mock_no_ip_packet = {'timestamp': ts_icmp, 'eth': {}} # No 'ip' field
        tracker.process_packet(mock_no_ip_packet)
        results_after_no_ip = tracker.get_results()
        self.assertEqual(len(results_after_no_ip), 1, "Packet without IP should not add new conversation")


    # --- Tests for DnsAnalyzer ---
    def test_dns_analyzer_queries_and_responses(self):
        analyzer = DnsAnalyzer()
        ts_q1 = datetime.datetime(2023,1,1,10,0,0, tzinfo=datetime.timezone.utc)
        ts_r1 = ts_q1 + datetime.timedelta(seconds=1)
        ts_q2 = ts_q1 + datetime.timedelta(seconds=2)

        # Query 1
        dns_q1_obj = dpkt.dns.DNS(id=123, qr=dpkt.dns.DNS_Q, qd=[dpkt.dns.DNS.Q(name='query1.com', type=dpkt.dns.DNS_A)])
        mock_dns_query1_data = {'timestamp': ts_q1, 'app_layer': {'type': 'DNS', 'data_obj': dns_q1_obj}}
        analyzer.process_packet(mock_dns_query1_data)

        # Response 1
        # Note: dpkt expects RR name to be bytes if it came from network, but for construction, string is fine.
        # The DnsAnalyzer converts names to strings for storage.
        dns_r1_obj = dpkt.dns.DNS(id=123, qr=dpkt.dns.DNS_R,
                                  an=[dpkt.dns.DNS.RR(name='query1.com', type=dpkt.dns.DNS_A, rdata=socket.inet_aton('1.2.3.4'), ttl=300)])
        # dpkt sets .ip from .rdata if type A/AAAA
        dns_r1_obj.an[0].ip = socket.inet_aton('1.2.3.4')
        mock_dns_response1_data = {'timestamp': ts_r1, 'app_layer': {'type': 'DNS', 'data_obj': dns_r1_obj}}
        analyzer.process_packet(mock_dns_response1_data)

        # Query 2 (different name, no response)
        dns_q2_obj = dpkt.dns.DNS(id=124, qr=dpkt.dns.DNS_Q, qd=[dpkt.dns.DNS.Q(name='query2.org', type=dpkt.dns.DNS_AAAA)])
        mock_dns_query2_data = {'timestamp': ts_q2, 'app_layer': {'type': 'DNS', 'data_obj': dns_q2_obj}}
        analyzer.process_packet(mock_dns_query2_data)

        # Query 1 again (to test counts)
        analyzer.process_packet(mock_dns_query1_data)


        results = analyzer.get_results(top_n=1) # top_n here is for top_queries

        self.assertEqual(len(results['query_log']), 3, "Should have logged 3 queries")
        self.assertEqual(results['query_log'][0]['name'], 'query1.com')
        self.assertEqual(results['query_log'][0]['id'], 123)

        self.assertIn(123, results['responses'], "Response for ID 123 should exist")
        self.assertEqual(len(results['responses'][123]), 1, "One response set for ID 123")
        self.assertEqual(len(results['responses'][123][0]['answers']), 1, "One answer in response for ID 123")
        answer1 = results['responses'][123][0]['answers'][0]
        self.assertEqual(answer1['name'], 'query1.com')
        self.assertEqual(answer1['atype'], dpkt.dns.DNS_A)
        self.assertEqual(answer1['val'], '1.2.3.4')
        self.assertEqual(answer1['ttl'], 300)

        self.assertNotIn(124, results['responses'], "No response for ID 124")

        self.assertEqual(len(results['top_queries']), 1, "Top queries should respect top_n")
        self.assertEqual(results['top_queries'][0], ('query1.com', 2), "query1.com count should be 2")

        # Test get_results with default top_n (should be 10, so all queries here)
        full_results = analyzer.get_results()
        self.assertEqual(len(full_results['top_queries']), 2) # query1.com, query2.org
        self.assertEqual(sorted(full_results['top_queries']), sorted([('query1.com', 2), ('query2.org', 1)]))


    def test_dns_analyzer_no_dns_packets(self):
        analyzer = DnsAnalyzer()
        mock_tcp_packet = { # Not a DNS packet
            'timestamp': datetime.datetime.now(tz=datetime.timezone.utc),
            'app_layer': {'type': 'TCP', 'data_obj': None}
        }
        analyzer.process_packet(mock_tcp_packet)
        analyzer.process_packet({}) # Empty packet data

        results = analyzer.get_results()
        self.assertEqual(len(results['query_log']), 0)
        self.assertEqual(len(results['responses']), 0)
        self.assertEqual(len(results['top_queries']), 0)

    # --- Tests for HttpAnalyzer ---
    def test_http_analyzer_requests(self):
        analyzer = HttpAnalyzer()
        ts1 = datetime.datetime(2023, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
        ts2 = ts1 + datetime.timedelta(seconds=1)
        ts3 = ts1 + datetime.timedelta(seconds=2)

        # Request 1 (GET)
        http_get_headers = collections.OrderedDict([('Host', 'example.com'), ('User-Agent', 'TestClient/1.0')])
        http_get_obj = dpkt.http.Request(method='GET', uri='/index.html', version='1.1', headers=http_get_headers, body=b'')
        mock_http_get_data = {
            'timestamp': ts1,
            'ip': {'src_ip_str': '192.168.1.10', 'dst_ip_str': '10.0.0.5'},
            'app_layer': {'type': 'HTTP', 'data_obj': http_get_obj}
        }
        analyzer.process_packet(mock_http_get_data)

        # Request 2 (POST to same host)
        http_post_headers = collections.OrderedDict([('Host', 'example.com'), ('Content-Type', 'application/x-www-form-urlencoded')])
        http_post_obj = dpkt.http.Request(method='POST', uri='/submit', version='1.1', headers=http_post_headers, body=b'data=test')
        mock_http_post_data = {
            'timestamp': ts2,
            'ip': {'src_ip_str': '192.168.1.11', 'dst_ip_str': '10.0.0.5'},
            'app_layer': {'type': 'HTTP', 'data_obj': http_post_obj}
        }
        analyzer.process_packet(mock_http_post_data)

        # Request 3 (GET to different host)
        http_get_headers_other = collections.OrderedDict([('Host', 'otherhost.org'), ('User-Agent', 'TestClient/1.0')])
        http_get_obj_other = dpkt.http.Request(method='GET', uri='/', version='1.1', headers=http_get_headers_other, body=b'')
        mock_http_get_data_other = {
            'timestamp': ts3,
            'ip': {'src_ip_str': '192.168.1.12', 'dst_ip_str': '10.0.0.6'},
            'app_layer': {'type': 'HTTP', 'data_obj': http_get_obj_other}
        }
        analyzer.process_packet(mock_http_get_data_other)

        results = analyzer.get_results(top_n=1) # top_n for top_hosts

        self.assertEqual(len(results['requests']), 3, "Should have logged 3 HTTP requests")

        # Check details of the first request
        req1_details = results['requests'][0]
        self.assertEqual(req1_details['ts'], ts1)
        self.assertEqual(req1_details['method'], 'GET')
        self.assertEqual(req1_details['uri'], '/index.html')
        self.assertEqual(req1_details['host'], 'example.com')
        self.assertEqual(req1_details['ua'], 'TestClient/1.0')
        self.assertEqual(req1_details['src_ip'], '192.168.1.10')
        self.assertEqual(req1_details['dst_ip'], '10.0.0.5')

        self.assertEqual(len(results['top_hosts']), 1, "Top hosts should respect top_n")
        self.assertEqual(results['top_hosts'][0], ('example.com', 2), "example.com count should be 2")

        full_results = analyzer.get_results() # Default top_n
        self.assertEqual(len(full_results['top_hosts']), 2)
        self.assertIn(('example.com', 2), full_results['top_hosts'])
        self.assertIn(('otherhost.org', 1), full_results['top_hosts'])


    def test_http_analyzer_no_http_packets(self):
        analyzer = HttpAnalyzer()
        mock_dns_packet = { # Not an HTTP packet
            'timestamp': datetime.datetime.now(tz=datetime.timezone.utc),
            'app_layer': {'type': 'DNS', 'data_obj': None}
        }
        analyzer.process_packet(mock_dns_packet)
        analyzer.process_packet({}) # Empty packet data

        results = analyzer.get_results()
        self.assertEqual(len(results['requests']), 0)
        self.assertEqual(len(results['top_hosts']), 0)

    def test_http_analyzer_http_response(self):
        analyzer = HttpAnalyzer()
        ts_resp = datetime.datetime(2023, 1, 1, 10, 0, 10, tzinfo=datetime.timezone.utc)

        http_resp_headers = collections.OrderedDict([('Content-Type', 'text/html')])
        http_resp_obj = dpkt.http.Response(version='1.1', status='200', reason='OK', headers=http_resp_headers, body=b'<html></html>')
        mock_http_resp_data = {
            'timestamp': ts_resp,
            'ip': {'src_ip_str': '10.0.0.5', 'dst_ip_str': '192.168.1.10'},
            'app_layer': {'type': 'HTTP', 'data_obj': http_resp_obj}
        }
        analyzer.process_packet(mock_http_resp_data)

        results = analyzer.get_results()
        self.assertEqual(len(results['requests']), 0, "HTTP Responses should not be added to requests list")
        self.assertEqual(len(results['top_hosts']), 0, "HTTP Responses should not update host counts")

    # --- Tests for TlsAnalyzer ---
    def test_tls_analyzer_client_hello_sni(self):
        analyzer = TlsAnalyzer()
        ts1 = datetime.datetime(2023, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)
        ts2 = ts1 + datetime.timedelta(seconds=1)

        # SNI Extension helper (simplified for testing _parse_tls_sni directly if needed, but here used for TlsAnalyzer)
        def create_sni_extension_bytes(server_name_str):
            server_name_bytes = server_name_str.encode('utf-8')
            # ServerNameList length (2 bytes), ServerName Type (1 byte, 0=host_name), ServerName length (2 bytes), ServerName
            server_name_entry = b'\x00' + len(server_name_bytes).to_bytes(2, 'big') + server_name_bytes
            # ServerNameList consists of one entry
            server_name_list = (len(server_name_entry)).to_bytes(2, 'big') + server_name_entry
            # TLSEXT_SERVER_NAME type (2 bytes), extension length (2 bytes), ServerNameList
            # This is the raw data for the TLSExtension data field.
            return dpkt.ssl.TLSExtension(type=dpkt.ssl.TLSEXT_SERVER_NAME, data=server_name_list)

        # Packet 1: Client Hello with SNI 'test1.example.com'
        sni_ext1 = create_sni_extension_bytes('test1.example.com')
        ch1 = dpkt.ssl.TLSClientHello(version=dpkt.ssl.TLS_V1_2, random=os.urandom(32), session_id=b'',
                                      cipher_suites=[dpkt.ssl.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
                                      comp_methods=[dpkt.ssl.TLS_COMP_NULL], extensions=[sni_ext1])
        hs1 = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_CLIENT_HELLO, data=ch1)
        # The TlsAnalyzer's _parse_tls_sni expects the extensions list/bytes directly from TLSClientHello
        # PacketParser stores dpkt.ssl.TLS as data_obj for app_layer if port is 443.
        # dpkt.ssl.TLS.data should be bytes of one or more TLSRecord structures.
        # For testing TlsAnalyzer, we need to simulate that PacketParser has already extracted the TLSHandshake part.
        # However, TlsAnalyzer.process_packet expects parsed_data['app_layer']['data_obj'] to be dpkt.ssl.TLS.
        # And TlsAnalyzer itself handles dpkt.ssl.TLSHandshake(tls_record.data)

        tls_record1_data = bytes(hs1) # This is what would be inside a TLSRecord of type Handshake
        tls_record1 = dpkt.ssl.TLS(type=dpkt.ssl.TLS_HANDSHAKE, version=dpkt.ssl.TLS_V1_2, data=tls_record1_data)

        mock_tls_ch1_data = {
            'timestamp': ts1,
            'ip': {'src_ip_str': '192.168.1.15', 'dst_ip_str': '10.0.0.7'},
            'app_layer': {'type': 'TLS', 'data_obj': tls_record1}
        }
        analyzer.process_packet(mock_tls_ch1_data)

        # Packet 2: Client Hello with SNI 'test2.example.com'
        sni_ext2 = create_sni_extension_bytes('test2.example.com')
        ch2 = dpkt.ssl.TLSClientHello(version=dpkt.ssl.TLS_V1_2, random=os.urandom(32), extensions=[sni_ext2])
        hs2 = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_CLIENT_HELLO, data=ch2)
        tls_record2_data = bytes(hs2)
        tls_record2 = dpkt.ssl.TLS(type=dpkt.ssl.TLS_HANDSHAKE, version=dpkt.ssl.TLS_V1_2, data=tls_record2_data)
        mock_tls_ch2_data = {
            'timestamp': ts2,
            'ip': {'src_ip_str': '192.168.1.16', 'dst_ip_str': '10.0.0.8'},
            'app_layer': {'type': 'TLS', 'data_obj': tls_record2}
        }
        analyzer.process_packet(mock_tls_ch2_data)

        # Packet 3: Client Hello again for 'test1.example.com'
        analyzer.process_packet(mock_tls_ch1_data) # Reprocess to check counts

        results = analyzer.get_results(top_n=1) # top_n for top_sni
        self.assertEqual(len(results['client_hellos_sni']), 3)
        self.assertEqual(results['client_hellos_sni'][0]['sni'], 'test1.example.com')
        self.assertEqual(results['client_hellos_sni'][0]['src'], '192.168.1.15')
        self.assertEqual(results['client_hellos_sni'][1]['sni'], 'test2.example.com')

        self.assertEqual(len(results['top_sni']), 1)
        self.assertEqual(results['top_sni'][0], ('test1.example.com', 2))

        full_results = analyzer.get_results()
        self.assertEqual(len(full_results['top_sni']), 2)
        self.assertIn(('test1.example.com', 2), full_results['top_sni'])
        self.assertIn(('test2.example.com', 1), full_results['top_sni'])

    def test_tls_analyzer_no_sni_or_not_client_hello(self):
        analyzer = TlsAnalyzer()
        ts = datetime.datetime(2023,1,1,11,0,5, tzinfo=datetime.timezone.utc)

        # Client Hello without SNI extension
        ch_no_sni = dpkt.ssl.TLSClientHello(version=dpkt.ssl.TLS_V1_2, random=os.urandom(32), extensions=[]) # No extensions
        hs_no_sni = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_CLIENT_HELLO, data=ch_no_sni)
        tls_rec_no_sni = dpkt.ssl.TLS(type=dpkt.ssl.TLS_HANDSHAKE, data=bytes(hs_no_sni))
        mock_tls_no_sni_data = {
            'timestamp': ts, 'ip': {}, 'app_layer': {'type': 'TLS', 'data_obj': tls_rec_no_sni}
        }
        analyzer.process_packet(mock_tls_no_sni_data)

        # Not a Client Hello (e.g., Server Hello)
        sh_data = b'\x03\x03' + os.urandom(32) + b'\x00' + b'\xc0\x2b' + b'\x00' # Version, Random, SessionID len 0, Cipher, Comp Method null
        hs_server_hello = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_SERVER_HELLO, data=sh_data ) # type=2
        tls_rec_sh = dpkt.ssl.TLS(type=dpkt.ssl.TLS_HANDSHAKE, data=bytes(hs_server_hello))
        mock_tls_sh_data = {
            'timestamp': ts, 'ip': {}, 'app_layer': {'type': 'TLS', 'data_obj': tls_rec_sh}
        }
        analyzer.process_packet(mock_tls_sh_data)

        results = analyzer.get_results()
        self.assertEqual(len(results['client_hellos_sni']), 0)
        self.assertEqual(len(results['top_sni']), 0)

    def test_tls_analyzer_malformed_sni_extension(self):
        analyzer = TlsAnalyzer()
        ts = datetime.datetime(2023,1,1,11,0,10, tzinfo=datetime.timezone.utc)

        # Malformed SNI data (e.g., length mismatch)
        malformed_sni_data = b'\x00\x0a\x00\x00\x07invalid' # List len 10, type 0, name len 7, but 'invalid' is not 7.
        malformed_ext = dpkt.ssl.TLSExtension(type=dpkt.ssl.TLSEXT_SERVER_NAME, data=malformed_sni_data)
        ch_mal_sni = dpkt.ssl.TLSClientHello(version=dpkt.ssl.TLS_V1_2, random=os.urandom(32), extensions=[malformed_ext])
        hs_mal_sni = dpkt.ssl.TLSHandshake(type=dpkt.ssl.TLS_HANDSHAKE_TYPE_CLIENT_HELLO, data=ch_mal_sni)
        tls_rec_mal_sni = dpkt.ssl.TLS(type=dpkt.ssl.TLS_HANDSHAKE, data=bytes(hs_mal_sni))
        mock_tls_mal_sni_data = {
            'timestamp': ts, 'ip': {}, 'app_layer': {'type': 'TLS', 'data_obj': tls_rec_mal_sni}
        }
        # The TlsAnalyzer._parse_tls_sni has its own try-except Exception.
        # We expect it to fail gracefully and not log an SNI.
        analyzer.process_packet(mock_tls_mal_sni_data)

        results = analyzer.get_results()
        self.assertEqual(len(results['client_hellos_sni']), 0)
        self.assertEqual(len(results['top_sni']), 0)


if __name__ == '__main__':
    unittest.main()
