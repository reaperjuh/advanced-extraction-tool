import os
import argparse
import datetime
import sys
import collections
import socket # For IP address formatting
import csv # For ReportGenerator

try:
    import dpkt
except ImportError:
    print("Error: dpkt library is not installed. Please install it (e.g., 'pip install dpkt').", file=sys.stderr)
    sys.exit(1)

# --- Helper to format MAC addresses ---
def format_mac(mac_bytes):
    """Formats MAC address bytes to a hex string."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

# --- Argument Parser Setup ---
def setup_parser():
    parser = argparse.ArgumentParser(description="Analyze PCAP files for network traffic patterns.")
    parser.add_argument("pcap_file", help="Path to the PCAP or PCAPng file to analyze.")
    parser.add_argument("--output-dir", help="Directory to save output CSV files. If not set, CSVs are not generated.")
    parser.add_argument("--filter", metavar="BPF_FILTER", help="BPF filter string to apply (placeholder, not implemented yet).")
    parser.add_argument("--ip-top-n", type=int, default=10, help="Number of top IP addresses to report (default: 10).")
    parser.add_argument("--dns-top-n", type=int, default=10, help="Number of top DNS queries to report (default: 10).")
    parser.add_argument("--http-top-n", type=int, default=10, help="Number of top HTTP hosts to report (default: 10).")
    parser.add_argument("--tls-top-n", type=int, default=10, help="Number of top TLS SNI hostnames to report (default: 10).")
    parser.add_argument("--conv-top-n", type=int, default=10, help="Number of top conversations to report (default: 10).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output during processing and for console summary.")
    return parser

# --- PCAP Reader Class ---
class PcapReader:
    def __init__(self, filepath, verbose=False):
        self.filepath = filepath; self.file_handle = None; self.reader = None
        self.linktype = None; self.is_pcapng = False
        try:
            self.file_handle = open(self.filepath, 'rb')
            try:
                self.reader = dpkt.pcapng.Reader(self.file_handle)
                self.is_pcapng = True; self.linktype = None
                try:
                    with open(self.filepath, 'rb') as temp_f:
                        temp_r = dpkt.pcapng.Reader(temp_f)
                        for blk_type, blk_body in temp_r:
                            if blk_type == dpkt.pcapng.PKT_IDB:
                                self.linktype = dpkt.pcapng.IDB(blk_body).linktype; break
                except Exception: pass
                if self.linktype is None: self.linktype = dpkt.pcap.DLT_EN10MB
                if verbose: print(f"Info: PCAPng. Linktype: {self.linktype if self.linktype else 'Unknown, assuming EN10MB'}.", file=sys.stderr)
            except ValueError:
                self.file_handle.seek(0)
                try:
                    self.reader = dpkt.pcap.Reader(self.file_handle)
                    self.linktype = self.reader.datalink(); self.is_pcapng = False
                    if verbose: print(f"Info: PCAP. Linktype: {self.linktype}", file=sys.stderr)
                except (dpkt.dpkt.Error, ValueError) as e: self.close(); raise ValueError(f"Format error: {e}") from e
            except Exception as e: self.close(); raise IOError(f"Error opening PCAPng '{self.filepath}': {e}") from e
        except FileNotFoundError: raise
        except IOError as e: self.close(); raise IOError(f"Error opening '{self.filepath}': {e}") from e
    def __iter__(self):
        if not self.reader: return iter([])
        if self.is_pcapng:
            for ts, buf, _ in self.reader: yield ts, buf
        else:
             for ts, buf in self.reader: yield ts, buf
    def close(self):
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.close(); self.file_handle = None

# --- Packet Parser Class ---
class PacketParser:
    def __init__(self): pass

    def _parse_ip_packet(self, ip_obj, parsed_data):
        """Helper to parse IP packet details and nested transport protocols."""
        if not ip_obj or not isinstance(ip_obj, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # This case should ideally be prevented by callers
            if not parsed_data.get('error'): # Avoid overwriting more specific error
                 parsed_data['error'] = "Invalid IP object passed to _parse_ip_packet"
            parsed_data['payload'] = parsed_data.get('payload', b'') # Ensure payload is bytes
            return

        ver = ip_obj.v
        src_b = ip_obj.src
        dst_b = ip_obj.dst
        proto = 0
        ip_len = 0
        ip_payload_buffer = ip_obj.data # This is the potential transport layer

        if ver == 4:
            proto = ip_obj.p
            ip_len = ip_obj.len
            parsed_data['ip'] = {'src_ip_bytes': src_b, 'dst_ip_bytes': dst_b, 'proto': proto, 'version': 4, 'len': ip_len,
                                 'src_ip_str': socket.inet_ntoa(src_b), 'dst_ip_str': socket.inet_ntoa(dst_b)}
        elif ver == 6:
            proto = ip_obj.nxt
            # IPv6 header length is fixed (40 bytes). len(ip_obj) includes header and payload.
            # ip_obj.plen is payload length.
            ip_len = len(ip_obj) # Total length (header + payload)
            parsed_data['ip'] = {'src_ip_bytes': src_b, 'dst_ip_bytes': dst_b, 'proto': proto, 'version': 6, 'len': ip_len,
                                 'src_ip_str': socket.inet_ntop(socket.AF_INET6, src_b), 'dst_ip_str': socket.inet_ntop(socket.AF_INET6, dst_b)}
        else:
            # Should not happen if ip_obj is validated as IP/IP6
            parsed_data['error'] = f"Unknown IP version: {ver}"
            parsed_data['payload'] = ip_payload_buffer if isinstance(ip_payload_buffer, bytes) else b''
            return

        parsed_data['transport_obj'] = ip_payload_buffer # Store the raw transport layer object
        parsed_data['payload'] = ip_payload_buffer # Default payload if no further parsing

        if not ip_payload_buffer: # No transport layer data
            return

        try:
            if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip_payload_buffer, dpkt.tcp.TCP):
                tcp = ip_payload_buffer
                parsed_data['transport'] = {'type': 'TCP', 'src_port': tcp.sport, 'dst_port': tcp.dport, 'flags': tcp.flags}
                parsed_data['payload'] = tcp.data
                # Basic HTTP/TLS detection by port
                if (tcp.sport == 80 or tcp.dport == 80) and len(tcp.data) > 0:
                    try: parsed_data['app_layer'] = {'type': 'HTTP', 'data_obj': dpkt.http.Request(tcp.data)}
                    except (dpkt.dpkt.Error, AttributeError):
                        try: parsed_data['app_layer'] = {'type': 'HTTP', 'data_obj': dpkt.http.Response(tcp.data)}
                        except (dpkt.dpkt.Error, AttributeError): pass
                elif (tcp.sport == 443 or tcp.dport == 443) and len(tcp.data) > 0:
                    try: parsed_data['app_layer'] = {'type': 'TLS', 'data_obj': dpkt.ssl.TLS(tcp.data)}
                    except (dpkt.dpkt.Error, AttributeError): pass
            elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip_payload_buffer, dpkt.udp.UDP):
                udp = ip_payload_buffer
                parsed_data['transport'] = {'type': 'UDP', 'src_port': udp.sport, 'dst_port': udp.dport}
                parsed_data['payload'] = udp.data
                if (udp.sport == 53 or udp.dport == 53) and len(udp.data) > 0:
                    try: parsed_data['app_layer'] = {'type': 'DNS', 'data_obj': dpkt.dns.DNS(udp.data)}
                    except (dpkt.dpkt.Error, AttributeError): pass
            elif proto == dpkt.ip.IP_PROTO_ICMP and isinstance(ip_payload_buffer, dpkt.icmp.ICMP):
                icmp = ip_payload_buffer
                parsed_data['transport'] = {'type': 'ICMP', 'icmp_type': icmp.type, 'icmp_code': icmp.code}
                parsed_data['payload'] = getattr(icmp.data, 'data', icmp.data) # Handle ICMP messages with and without sub-structures
            elif proto == dpkt.ip.IP_PROTO_ICMPV6 and isinstance(ip_payload_buffer, dpkt.icmp6.ICMP6):
                icmp6 = ip_payload_buffer
                parsed_data['transport'] = {'type': 'ICMPv6', 'icmp_type': icmp6.type, 'icmp_code': icmp6.code}
                parsed_data['payload'] = getattr(icmp6.data, 'data', icmp6.data)
            # else: other transport protocols not specifically parsed, payload remains ip_payload_buffer
        except dpkt.dpkt.Error as e_trans: # Error during transport layer parsing
            parsed_data['error'] = parsed_data.get('error', "") + f" TransportParseError: {e_trans}"
            # Payload is already set to ip_payload_buffer, which is correct here
        except Exception as e_gen_trans: # More general error
            parsed_data['error'] = parsed_data.get('error', "") + f" GenericTransportParseError: {e_gen_trans}"


    def parse_packet(self, timestamp_s, buf, linktype):
        parsed = {'timestamp': datetime.datetime.fromtimestamp(timestamp_s, tz=datetime.timezone.utc),
                  'linktype_str': 'Unknown', 'eth': None, 'sll': None, 'loopback': None,
                  'ip': None, 'arp': None, 'transport_obj': None, 'payload': buf,
                  'transport': None, 'app_layer': None, 'error': None, 'raw_buffer_len': len(buf)}

        ip_obj = None
        data_after_link_layer = buf # Initial assumption for payload if no link layer is parsed or it's raw

        try:
            if linktype == dpkt.pcap.DLT_EN10MB:
                parsed['linktype_str'] = 'Ethernet'
                eth_frame = dpkt.ethernet.Ethernet(buf)
                parsed['eth'] = {'src_mac_str': format_mac(eth_frame.src),
                                 'dst_mac_str': format_mac(eth_frame.dst),
                                 'type': eth_frame.type}
                data_after_link_layer = eth_frame.data
                parsed['payload'] = data_after_link_layer

                if eth_frame.type == dpkt.ethernet.ETH_TYPE_ARP:
                    arp_pkt = dpkt.arp.ARP(data_after_link_layer)
                    parsed['arp'] = {
                        'op_str': {dpkt.arp.ARP_OP_REQUEST: "REQUEST", dpkt.arp.ARP_OP_REPLY: "REPLY"}.get(arp_pkt.op, f"OP_{arp_pkt.op}"),
                        'src_hw_addr_str': format_mac(arp_pkt.sha), 'src_proto_addr_str': socket.inet_ntoa(arp_pkt.spa),
                        'dst_hw_addr_str': format_mac(arp_pkt.tha), 'dst_proto_addr_str': socket.inet_ntoa(arp_pkt.tpa)
                    }
                    # ARP is not IP, so ip_obj remains None. Payload is arp_pkt.data or handled by collectors if needed.
                elif eth_frame.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip_obj = dpkt.ip.IP(data_after_link_layer)
                elif eth_frame.type == dpkt.ethernet.ETH_TYPE_IP6:
                    ip_obj = dpkt.ip6.IP6(data_after_link_layer)
                else:
                    parsed['error'] = f"Unknown Ethernet type: {hex(eth_frame.type)}"
                    # payload already set to eth_frame.data

            elif linktype == dpkt.pcap.DLT_LINUX_SLL:
                parsed['linktype_str'] = 'Linux SLL'
                sll = dpkt.sll.SLL(buf)
                # sll.sender is the address, sll.halen is its length
                addr_str = format_mac(sll.sender) if sll.halen == 6 else str(sll.sender) # hexlify non-MAC addrs?
                parsed['sll'] = {'pkttype': sll.pkttype, 'hatype': sll.hatype,
                                 'addrlen': sll.halen, 'addr_bytes': sll.sender,
                                 'addr_str': addr_str, 'type': sll.type}
                data_after_link_layer = sll.data
                parsed['payload'] = data_after_link_layer

                if sll.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip_obj = dpkt.ip.IP(data_after_link_layer)
                elif sll.type == dpkt.ethernet.ETH_TYPE_IP6:
                    ip_obj = dpkt.ip6.IP6(data_after_link_layer)
                else:
                    parsed['error'] = f"Unknown SLL type: {hex(sll.type)}"
                    # payload already set to sll.data

            elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
                # DLT_LOOP (108 for OpenBSD) might have different struct, dpkt.loopback handles common DLT_NULL (family prefix)
                parsed['linktype_str'] = f'Loopback/Null({linktype})' # Keep linktype to distinguish if needed
                loop = dpkt.loopback.Loopback(buf) # dpkt.loopback.Loopback expects family in host byte order for DLT_NULL
                parsed['loopback'] = {'family': loop.family}
                data_after_link_layer = loop.data
                parsed['payload'] = data_after_link_layer

                if loop.family == socket.AF_INET:
                    ip_obj = dpkt.ip.IP(data_after_link_layer)
                elif loop.family == socket.AF_INET6:
                    ip_obj = dpkt.ip6.IP6(data_after_link_layer)
                else:
                    parsed['error'] = f"Unknown DLT_NULL/Loopback family: {loop.family}"
                    # payload already set to loop.data

            elif linktype == dpkt.pcap.DLT_RAW:
                # No link layer header, buffer is directly an IP packet (hopefully)
                data_after_link_layer = buf # This is the IP packet itself
                parsed['payload'] = data_after_link_layer
                try:
                    temp_ip = dpkt.ip.IP(buf)
                    if temp_ip.v == 4:
                        ip_obj = temp_ip
                        parsed['linktype_str'] = 'Raw IPv4'
                    else: # Not v4, try v6 before generic error
                        raise dpkt.dpkt.Error("Not IPv4, try IPv6") # force fallback to IPv6 try block
                except (dpkt.dpkt.Error, AttributeError, struct.error): # struct.error for short packets
                    try:
                        temp_ip6 = dpkt.ip6.IP6(buf)
                        if temp_ip6.v == 6:
                            ip_obj = temp_ip6
                            parsed['linktype_str'] = 'Raw IPv6'
                        else: # Should not happen if it's a valid IP6 object
                             parsed['error'] = "DLT_RAW: Parsed as IP6 but unknown version"
                    except (dpkt.dpkt.Error, AttributeError, struct.error):
                        parsed['linktype_str'] = 'Raw (Unknown IP Version)'
                        parsed['error'] = "DLT_RAW: Could not be reliably parsed as IPv4 or IPv6"
                        # payload is already buf

            else:
                parsed['error'] = f"Unsupported linktype: {linktype}"
                parsed['payload'] = buf # Keep original buffer as payload

            # If an IP object was created (from any linktype), parse it
            if ip_obj:
                self._parse_ip_packet(ip_obj, parsed)
            # If no IP object, and not ARP, and no error yet, payload is data_after_link_layer
            # This is mostly covered by initial parsed['payload'] = data_after_link_layer or buf
            # and specific error branches setting their respective payloads.

        except dpkt.dpkt.Error as e_link: # Errors during link-layer parsing (e.g. Ethernet, SLL)
            parsed['error'] = f"DPKT Link Error: {e_link} (Linktype: {linktype})"
            parsed['payload'] = buf # On link error, payload is the raw buffer
        except Exception as e_generic: # Catch-all for other unexpected errors
            parsed['error'] = f"Generic parsing error: {e_generic} (Type: {type(e_generic).__name__}, Linktype: {linktype})"
            parsed['payload'] = buf

        # Ensure payload is bytes
        if not isinstance(parsed.get('payload'), bytes):
            parsed['payload'] = b''

        return parsed

# --- Collector Classes ---
class SummaryStatsCollector:
    def __init__(self): self.total_packets=0; self.total_bytes=0; self.first_packet_ts=None; self.last_packet_ts=None; self.linktypes_seen=collections.Counter()
    def process_packet(self,ts_dt,buf_len,link_str): self.total_packets+=1; self.total_bytes+=buf_len; self.linktypes_seen[link_str]+=1; self.last_packet_ts=ts_dt; self.first_packet_ts=self.first_packet_ts or ts_dt
    def get_results(self): dur=(self.last_packet_ts-self.first_packet_ts).total_seconds() if self.first_packet_ts and self.last_packet_ts and self.last_packet_ts > self.first_packet_ts else 0; return {'total_packets':self.total_packets,'total_bytes':self.total_bytes,'first_ts':self.first_packet_ts.isoformat() if self.first_packet_ts else 'N/A','last_ts':self.last_packet_ts.isoformat() if self.last_packet_ts else 'N/A','duration_sec':round(dur,3),'avg_pkt_size':round(self.total_bytes/self.total_packets,2) if self.total_packets else 0,'avg_rate_bps':round((self.total_bytes*8)/dur,2) if dur>0 else 0,'linktypes':dict(self.linktypes_seen)}
class ProtocolDistributionCollector:
    def __init__(self): self.l2_types=collections.Counter(); self.ip_versions=collections.Counter(); self.transport_protos=collections.Counter(); self.app_ports=collections.Counter()
    def process_packet(self,pdata):
        if pdata.get('eth'): self.l2_types[hex(pdata['eth']['type'])]+=1
        if pdata.get('arp'): self.ip_versions['ARP']+=1
        if pdata.get('ip'):
            ip_ver=pdata['ip'].get('version'); proto=pdata['ip'].get('proto')
            if ip_ver==4: self.ip_versions['IPv4']+=1;
            elif ip_ver==6: self.ip_versions['IPv6']+=1;
            if pdata.get('transport'):
                ttype=pdata['transport']['type']; self.transport_protos[ttype]+=1
                sp=pdata['transport'].get('src_port'); dp=pdata['transport'].get('dst_port')
                if proto in [dpkt.ip.IP_PROTO_UDP, dpkt.ip.IP_PROTO_TCP]:
                    if sp==53 or dp==53: self.app_ports['DNS(53)']+=1
                    if sp==80 or dp==80: self.app_ports['HTTP(80)']+=1
                    if sp==443 or dp==443: self.app_ports['TLS(443)']+=1
    def get_results(self): return {'l2_eth_types':dict(self.l2_types),'ip_versions':dict(self.ip_versions),'transport_protocols':dict(self.transport_protos),'app_layer_ports_heuristic':dict(self.app_ports)}
class IpUsageCollector:
    def __init__(self): self.src_ip_counts=collections.Counter(); self.dst_ip_counts=collections.Counter()
    def process_packet(self,pdata):
        if pdata.get('ip'):
            ip_info=pdata['ip']; src_s=ip_info.get('src_ip_str'); dst_s=ip_info.get('dst_ip_str')
            if src_s: self.src_ip_counts[src_s]+=1
            if dst_s: self.dst_ip_counts[dst_s]+=1
    def get_results(self,top_n=10): return {'top_src_ips':self.src_ip_counts.most_common(top_n),'top_dst_ips':self.dst_ip_counts.most_common(top_n)}
class ConversationTracker:
    def __init__(self): self.conversations={}
    def _get_canonical_key(self,ip_s_b,ip_d_b,p,sp,dp):
        if p not in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP] or (sp == 0 and dp == 0):
             return tuple(sorted((ip_s_b, ip_d_b))) + (p,0,0)
        return tuple(sorted(((ip_s_b,sp),(ip_d_b,dp))))+(p,)
    def process_packet(self,pdata):
        if pdata.get('ip'):
            ip_i=pdata['ip']; tr_i=pdata.get('transport')
            pkt_l=ip_i.get('len',pdata.get('raw_buffer_len',0))
            sp = tr_i.get('src_port', 0) if tr_i else 0; dp = tr_i.get('dst_port', 0) if tr_i else 0
            k=self._get_canonical_key(ip_i['src_ip_bytes'],ip_i['dst_ip_bytes'],ip_i['proto'],sp,dp)
            is_tcp_or_udp = k[2] in [dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP]
            conv=self.conversations.setdefault(k,{'ip1_b':k[0][0] if is_tcp_or_udp else k[0],
                                                'port1':k[0][1] if is_tcp_or_udp else k[3],
                                                'ip2_b':k[1][0] if is_tcp_or_udp else k[1],
                                                'port2':k[1][1] if is_tcp_or_udp else k[4],
                                                'proto':k[2],'pkts12':0,'bytes12':0,'pkts21':0,'bytes21':0,
                                                'first_ts':pdata['timestamp'],'last_ts':pdata['timestamp'],
                                                'tcp_flags':collections.Counter() if tr_i and tr_i.get('type')=='TCP' else None})
            is_1to2 = (ip_i['src_ip_bytes'] == conv['ip1_b'] and (not is_tcp_or_udp or sp == conv['port1']))
            if is_1to2: conv['pkts12']+=1; conv['bytes12']+=pkt_l
            else: conv['pkts21']+=1; conv['bytes21']+=pkt_l
            conv['last_ts']=max(conv['last_ts'],pdata['timestamp'])
            if tr_i and tr_i.get('type')=='TCP' and conv['tcp_flags'] is not None:
                f=tr_i.get('flags',0); tc=conv['tcp_flags']
                if f&dpkt.tcp.TH_SYN: tc['SYN']+=1
                if f&dpkt.tcp.TH_FIN: tc['FIN']+=1
                if f&dpkt.tcp.TH_RST: tc['RST']+=1
                if f&dpkt.tcp.TH_ACK: tc['ACK']+=1
                if f&dpkt.tcp.TH_PUSH: tc['PSH']+=1
                if f&dpkt.tcp.TH_URG: tc['URG']+=1
    def get_results(self,sort_by='total_packets',top_n=None):
        res=[]
        for _,d in self.conversations.items():
            item=d.copy(); v4_1=len(d['ip1_b'])==4; v4_2=len(d['ip2_b'])==4
            item['ip1_s']=socket.inet_ntoa(d['ip1_b']) if v4_1 else socket.inet_ntop(socket.AF_INET6,d['ip1_b'])
            item['ip2_s']=socket.inet_ntoa(d['ip2_b']) if v4_2 else socket.inet_ntop(socket.AF_INET6,d['ip2_b'])
            item['total_pkts']=d['pkts12']+d['pkts21']; item['total_bytes']=d['bytes12']+d['bytes21']
            item['duration_s']=round((d['last_ts']-d['first_ts']).total_seconds(),3) if d['last_ts']>d['first_ts'] else 0
            if item['tcp_flags'] is not None: item['tcp_flags']=dict(item['tcp_flags'])
            res.append(item)
        rev=True if sort_by in ['total_packets','total_bytes'] else False
        res.sort(key=lambda x:x.get(sort_by,0),reverse=rev)
        return res[:top_n] if top_n else res
class DnsAnalyzer:
    def __init__(self): self.queries=collections.Counter(); self.responses={}; self.query_log=[]
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='DNS' and pdata['app_layer']['data_obj']:
            dns=pdata['app_layer']['data_obj'];ts=pdata['timestamp']
            if not isinstance(dns,dpkt.dns.DNS):return
            if dns.qr==dpkt.dns.DNS_Q and dns.qd:
                for q in dns.qd:self.queries[q.name]+=1;self.query_log.append({'ts':ts,'id':dns.id,'name':q.name,'qtype':q.type})
            elif dns.qr==dpkt.dns.DNS_R and dns.an:
                ans=[]
                for rr in dns.an:
                    val=None; name_str = rr.name.decode('utf-8','ignore') if isinstance(rr.name, bytes) else rr.name
                    if hasattr(rr,'ip'):val=socket.inet_ntoa(rr.ip)
                    elif hasattr(rr,'ip6'):val=socket.inet_ntop(socket.AF_INET6,rr.ip6)
                    elif hasattr(rr,'cname'):val=rr.cname.decode('utf-8','ignore') if isinstance(rr.cname,bytes) else rr.cname
                    elif hasattr(rr,'ptrname'):val=rr.ptrname.decode('utf-8','ignore') if isinstance(rr.ptrname,bytes) else rr.ptrname
                    elif hasattr(rr,'mxname'):val=rr.mxname.decode('utf-8','ignore') if isinstance(rr.mxname,bytes) else rr.mxname
                    elif hasattr(rr,'nsname'):val=rr.nsname.decode('utf-8','ignore') if isinstance(rr.nsname,bytes) else rr.nsname
                    elif hasattr(rr,'mname'):val=rr.mname.decode('utf-8','ignore') if isinstance(rr.mname,bytes) else rr.mname
                    else:val="Other/Data"
                    ans.append({'name':name_str,'atype':rr.type,'val':val,'ttl':rr.ttl})
                if ans:self.responses.setdefault(dns.id,[]).append({'ts':ts,'answers':ans})
    def get_results(self,top_n=10):return{'top_queries':self.queries.most_common(top_n),'query_log':self.query_log,'responses':self.responses}
class HttpAnalyzer:
    def __init__(self): self.requests=[]; self.host_counts=collections.Counter()
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='HTTP' and pdata['app_layer']['data_obj']:
            http = pdata['app_layer']['data_obj']
            if isinstance(http, dpkt.http.Request):
                host=http.headers.get('host','N/A')
                self.requests.append({'ts':pdata['timestamp'],'method':http.method,'uri':http.uri,'ver':http.version,'host':host,'ua':http.headers.get('user-agent','N/A'), 'src_ip': pdata.get('ip',{}).get('src_ip_str','N/A'), 'dst_ip': pdata.get('ip',{}).get('dst_ip_str','N/A')})
                if host!='N/A': self.host_counts[host]+=1
    def get_results(self,top_n=10): return {'requests':self.requests[-top_n*20:], 'top_hosts':self.host_counts.most_common(top_n)}
class TlsAnalyzer:
    def __init__(self): self.client_hellos_sni=[]; self.sni_counts=collections.Counter()
    def _parse_tls_sni(self, ext_data):
        if not ext_data: return None
        try:
            if isinstance(ext_data, list):
                for ext_type, ext_val_bytes in ext_data:
                    if ext_type == dpkt.ssl.TLSEXT_SERVER_NAME:
                        if len(ext_val_bytes) < 2: continue
                        sni_list_len = int.from_bytes(ext_val_bytes[:2], 'big'); current_pos = 2
                        while current_pos + 3 <= len(ext_val_bytes) and current_pos < sni_list_len + 2 :
                            name_type = ext_val_bytes[current_pos]; current_pos += 1
                            name_len = int.from_bytes(ext_val_bytes[current_pos:current_pos+2], 'big'); current_pos += 2
                            if name_type == dpkt.ssl.TLS_SERVER_NAME_HOSTNAME:
                                if current_pos + name_len <= len(ext_val_bytes): return ext_val_bytes[current_pos:current_pos+name_len].decode('utf-8','ignore')
                                else: break
                            current_pos += name_len
                        return None
            elif isinstance(ext_data, bytes):
                idx=0;total_ext_len=int.from_bytes(ext_data[idx:idx+2],'big');idx+=2;parsed_len=0
                while parsed_len<total_ext_len and idx+4<=len(ext_data):
                    ext_type=int.from_bytes(ext_data[idx:idx+2],'big');idx+=2
                    ext_len=int.from_bytes(ext_data[idx:idx+2],'big');idx+=2
                    if ext_type==dpkt.ssl.TLSEXT_SERVER_NAME:
                        if idx+ext_len>len(ext_data) or ext_len<2:break
                        sni_list_len=int.from_bytes(ext_data[idx:idx+2],'big');idx_sni=idx+2;parsed_sni_list_len=0
                        while parsed_sni_list_len<sni_list_len and idx_sni+3<=len(ext_data):
                            name_type=ext_data[idx_sni];idx_sni+=1;name_len=int.from_bytes(ext_data[idx_sni:idx_sni+2],'big');idx_sni+=2
                            if name_type==dpkt.ssl.TLS_SERVER_NAME_HOSTNAME:
                                if idx_sni+name_len<=len(ext_data):return ext_data[idx_sni:idx_sni+name_len].decode('utf-8','ignore')
                                else:break
                            idx_sni+=name_len;parsed_sni_list_len=idx_sni-(idx+2)
                        break
                    idx+=ext_len;parsed_len=idx-2
        except Exception: return None
        return None
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='TLS' and pdata['app_layer']['data_obj']:
            tls_record = pdata['app_layer']['data_obj']
            if not isinstance(tls_record, dpkt.ssl.TLS) or not hasattr(tls_record, 'data') or not isinstance(tls_record.data, bytes) or tls_record.type != dpkt.ssl.TLS_HANDSHAKE: return
            try:
                handshake = dpkt.ssl.TLSHandshake(tls_record.data)
                if not isinstance(handshake, list): handshake = [handshake]
                for msg in handshake:
                    if hasattr(msg, 'data') and isinstance(msg.data, dpkt.ssl.TLSClientHello):
                        ch = msg.data; sni = None
                        if hasattr(ch, 'extensions') and ch.extensions: sni = self._parse_tls_sni(ch.extensions)
                        if not sni and hasattr(ch, 'extensions_bytes'): sni = self._parse_tls_sni(ch.extensions_bytes)
                        if sni:
                            src_ip=pdata.get('ip',{}).get('src_ip_str','N/A'); dst_ip=pdata.get('ip',{}).get('dst_ip_str','N/A')
                            self.client_hellos_sni.append({'ts':pdata['timestamp'],'sni':sni,'src':src_ip,'dst':dst_ip})
                            self.sni_counts[sni]+=1
            except dpkt.dpkt.Error: pass
    def get_results(self,top_n=10): return {'client_hellos_sni':self.client_hellos_sni[-top_n*5:], 'top_sni':self.sni_counts.most_common(top_n)}

# --- Report Generator Class ---
class ReportGenerator:
    def __init__(self, args): self.args=args; self.output_dir=os.path.abspath(args.output_dir) if args.output_dir else None; os.makedirs(self.output_dir,exist_ok=True) if self.output_dir else None
    def _ft(self,dt): return dt.isoformat() if dt else 'N/A'
    def _ff(self,fc): return ",".join([f"{f}:{c}" for f,c in fc.items()]) if fc else ""
    def _wc(self,fn,h,rd):
        if not self.output_dir:
            if self.args.verbose: print(f"Skipping CSV '{fn}' (no output dir).", file=sys.stderr)
            return False
        fp=os.path.join(self.output_dir,fn)
        try:
            with open(fp,'w',newline='',encoding='utf-8') as f: w=csv.writer(f);w.writerow(h);w.writerows([[str(c) if c is not None else "" for c in r] for r in rd])
            if self.args.verbose:print(f"CSV: {fp}",file=sys.stderr); return True
        except IOError as e:print(f"Error writing {fp}:{e}",file=sys.stderr);return False
    def print_console_summary(self, res):
        print("\n--- Summary Statistics ---");[print(f"  {k.replace('_',' ').title()}: {v}") for k,v in res['summary_stats'].items()]
        print("\n--- Protocol Distribution ---")
        for cat,data in res['proto_dist'].items(): print(f"  {cat.replace('_',' ').title()}:");print("    (No data)" if not data else "\n".join([f"    {p}: {c}" for p,c in sorted(data.items(),key=lambda x:x[1],reverse=True)]))
        ip_u=res['ip_usage'];print(f"\n--- Top {self.args.ip_top_n} Source IPs ---");[print(f"  {i}: {c}") for i,c in ip_u['top_src_ips'][:self.args.ip_top_n]]
        print(f"\n--- Top {self.args.ip_top_n} Destination IPs ---");[print(f"  {i}: {c}") for i,c in ip_u['top_dst_ips'][:self.args.ip_top_n]]
        convs=res['conversations'];print(f"\n--- Top {self.args.conv_top_n} Conversations ---")
        for i,c in enumerate(convs[:self.args.conv_top_n]):print(f"  {i+1}. {c['ip1_s']}:{c['port1']} <-> {c['ip2_s']}:{c['port2']} (P:{c['proto']}) Pkts:{c['total_pkts']} Bytes:{c['total_bytes']} Dur:{c['duration_s']:.3f}s TCP Flags:{self._ff(c['tcp_flags'])}")
        dns=res['dns_analysis'];print(f"\n--- Top {self.args.dns_top_n} DNS Queries ---");[print(f"  {n}: {c}") for n,c in dns['top_queries'][:self.args.dns_top_n]]
        if self.args.verbose and dns['query_log']: print("  Last 5 DNS Queries:");[print(f"    {self._ft(q['ts'])} ID:{q['id']} Name:{q['name']} Type:{q['qtype']}") for q in dns['query_log'][-5:]]
        http=res['http_analysis'];print(f"\n--- Top {self.args.http_top_n} HTTP Hosts ---");[print(f"  {h}: {c}") for h,c in http['top_hosts'][:self.args.http_top_n]]
        if self.args.verbose and http['requests']: print("  Last 5 HTTP Requests:");[print(f"    {self._ft(r['ts'])} {r['method']} {r['host']}{r['uri']}") for r in http['requests'][-5:]]
        tls=res['tls_analysis'];print(f"\n--- Top {self.args.tls_top_n} TLS SNIs ---");[print(f"  {s}: {c}") for s,c in tls['top_sni'][:self.args.tls_top_n]]
        if self.args.verbose and tls['client_hellos_sni']: print("  Last 5 TLS SNIs:");[print(f"    {self._ft(h['ts'])} SNI:{h['sni']} (Src:{h['src']},Dst:{h['dst']})") for h in tls['client_hellos_sni'][-5:]]
    def generate_csv_outputs(self, res):
        if not self.output_dir: return
        self._wc("summary_stats.csv",["Stat","Val"],list(res['summary_stats'].items()))
        pd_r=[];[[pd_r.append([cat,p,c])for p,c in data.items()]for cat,data in res['proto_dist'].items()];self._wc("protocol_distribution.csv",["Cat","Proto","Count"],pd_r)
        self._wc("ip_source_summary.csv",["IP","Count"],res['ip_usage']['top_src_ips'])
        self._wc("ip_destination_summary.csv",["IP","Count"],res['ip_usage']['top_dst_ips'])
        conv_h=["SrcIP","DstIP","SrcPort","DstPort","Proto","Pkts12","Bytes12","Pkts21","Bytes21","FirstTS","LastTS","DurSec","TCPFlags"]
        conv_r=[[c['ip1_s'],c['ip2_s'],c['port1'],c['port2'],c['proto'],c['pkts12'],c['bytes12'],c['pkts21'],c['bytes21'],self._ft(c['first_ts']),self._ft(c['last_ts']),c['duration_s'],self._ff(c['tcp_flags'])if c['tcp_flags']else"N/A"]for c in res['conversations']]
        self._wc("conversations.csv",conv_h,conv_r)
        dns_h=["TS_UTC","ID","Name","QType"];dns_r=[[self._ft(q['ts']),q['id'],q['name'],q['qtype']]for q in res['dns_analysis']['query_log']];self._wc("dns_queries.csv",dns_h,dns_r)
        self._wc("dns_top_queried_names.csv",["Name","Count"],res['dns_analysis']['top_queries'])
        http_h=["TS_UTC","SrcIP","DstIP","Method","Host","URI","UA","Ver"];http_r=[[self._ft(r['ts']),r['src_ip'],r['dst_ip'],r['method'],r['host'],r['uri'],r['ua'],r['ver']]for r in res['http_analysis']['requests']];self._wc("http_requests.csv",http_h,http_r)
        self._wc("http_top_hosts.csv",["Host","Count"],res['http_analysis']['top_hosts'])
        tls_h=["TS_UTC","SrcIP","DstIP","SNI"];tls_r=[[self._ft(h['ts']),h['src'],h['dst'],h['sni']]for h in res['tls_analysis']['client_hellos_sni']];self._wc("tls_client_hellos_sni.csv",tls_h,tls_r)
        self._wc("tls_top_sni.csv",["SNI","Count"],res['tls_analysis']['top_sni'])

# --- Main ---
if __name__ == '__main__':
    args = setup_parser().parse_args()
    if not os.path.exists(args.pcap_file): print(f"Error: PCAP file '{args.pcap_file}' not found.", file=sys.stderr); sys.exit(1)
    collectors = [SummaryStatsCollector(),ProtocolDistributionCollector(),IpUsageCollector(),ConversationTracker(),DnsAnalyzer(),HttpAnalyzer(),TlsAnalyzer()]
    try:
        pcap_reader = PcapReader(args.pcap_file, verbose=args.verbose)
        packet_parser = PacketParser()
        if args.verbose: print(f"Opened PCAP: {args.pcap_file}, Linktype: {pcap_reader.linktype}")
        limit = 50 if not args.verbose else float('inf'); count = 0
        for i,(ts,buf) in enumerate(pcap_reader):
            count=i+1
            if i>=limit and not args.verbose: print(f"\nProcessed first {limit} packets. Use --verbose for all."); break
            parsed = packet_parser.parse_packet(ts,buf,pcap_reader.linktype)
            for c in collectors: c.process_packet(parsed)
            if args.verbose: print(f"\n--- Pkt {i+1} ---\n  TS: {parsed['timestamp'].isoformat()}\n  Link: {parsed['linktype_str']} (Len: {parsed['raw_buffer_len']})", "".join([f"\n  Eth: Src:{p['eth']['src_mac_str']},Dst:{p['eth']['dst_mac_str']},T:{hex(p['eth']['type'])}" if (p:=parsed).get('eth') else ""]), "".join([f"\n  IP: V:{p['ip']['version']},Src:{p['ip']['src_ip_str']},Dst:{p['ip']['dst_ip_str']},Proto:{p['ip']['proto']}" if (p:=parsed).get('ip') else ""]), "".join([f"\n  Transport({(t:=p['transport'])['type']}): Sport:{t.get('src_port','N/A')},Dport:{t.get('dst_port','N/A')}" if (p:=parsed).get('transport') else ""]), "".join([f"\n  App: {p['app_layer']['type']}" if (p:=parsed).get('app_layer') else ""]), "".join([f"\n  Err: {p['error']}" if (p:=parsed).get('error') else ""]))
        pcap_reader.close()
        if args.verbose or (count > limit and not args.verbose) : print(f"\nProcessed {count} total packets.") # Corrected condition
        all_res={'summary_stats':collectors[0].get_results(),'proto_dist':collectors[1].get_results(),'ip_usage':collectors[2].get_results(None),'conversations':collectors[3].get_results(top_n=None, sort_by='total_packets'),'dns_analysis':collectors[4].get_results(None),'http_analysis':collectors[5].get_results(None),'tls_analysis':collectors[6].get_results(None)}
        report_gen = ReportGenerator(args) # Instantiate once
        report_gen.print_console_summary(all_res)
        report_gen.generate_csv_outputs(all_res)
    except (IOError,ValueError,dpkt.dpkt.Error) as e: print(f"Error: {e}",file=sys.stderr);sys.exit(1)
    except Exception as e: print(f"An unexpected error occurred: {e}",file=sys.stderr);sys.exit(1)
    print("\nPCAP analysis finished.")
[end of pcap_analyzer.py]

[start of test_pcap_analyzer.py]
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
        mock_file_open.assert_any_call("dummy.pcap", 'rb')
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
        self.assertEqual(parsed_data['eth']['src_mac_str'], format_mac(src_mac_bytes)) # Changed from src_mac
        self.assertEqual(parsed_data['eth']['dst_mac_str'], format_mac(dst_mac_bytes)) # Changed from dst_mac
        self.assertEqual(parsed_data['eth']['type'], dpkt.ethernet.ETH_TYPE_IP)

        self.assertIsNotNone(parsed_data['ip'])
        self.assertEqual(parsed_data['ip']['version'], 4)
        self.assertEqual(parsed_data['ip']['src_ip_str'], src_ip_str)
        self.assertEqual(parsed_data['ip']['dst_ip_str'], dst_ip_str)
        self.assertEqual(parsed_data['ip']['proto'], dpkt.ip.IP_PROTO_TCP)
        self.assertIsNotNone(parsed_data['transport'])
        self.assertEqual(parsed_data['transport']['type'], 'TCP')
        self.assertEqual(parsed_data['payload'], tcp_payload)
        self.assertIsNone(parsed_data['error'])

    def test_parse_eth_ipv6_frame(self):
        src_mac_bytes = b'\x10\x11\x12\x13\x14\x15'
        dst_mac_bytes = b'\x16\x17\x18\x19\x1a\x1b'
        src_ip_str = '2001:db8::1'; dst_ip_str = '2001:db8::2'
        udp_payload = b'UDP Segment'

        udp_obj = dpkt.udp.UDP(sport=54321, dport=53, data=udp_payload)
        udp_obj.ulen = len(udp_obj)

        ipv6_obj = _build_ipv6_packet_obj(payload=bytes(udp_obj), src_ip_str=src_ip_str, dst_ip_str=dst_ip_str, proto=dpkt.ip.IP_PROTO_UDP)
        eth_frame_bytes = _build_eth_packet(eth_type=dpkt.ethernet.ETH_TYPE_IP6, payload=bytes(ipv6_obj), src_mac=src_mac_bytes, dst_mac=dst_mac_bytes) # ETH_TYPE_IP6

        parsed_data = self.packet_parser.parse_packet(2.0, eth_frame_bytes, dpkt.pcap.DLT_EN10MB)

        self.assertEqual(parsed_data['linktype_str'], 'Ethernet')
        self.assertIsNotNone(parsed_data['eth'])
        self.assertEqual(parsed_data['eth']['type'], dpkt.ethernet.ETH_TYPE_IP6) # ETH_TYPE_IP6

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
        dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff' # ARP request typically broadcast
        src_ip_str = '192.168.1.100'; target_ip_str = '192.168.1.1'

        arp_obj = dpkt.arp.ARP(
            sha=src_mac_bytes, spa=socket.inet_aton(src_ip_str),
            tha=b'\x00\x00\x00\x00\x00\x00', tpa=socket.inet_aton(target_ip_str),
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
        self.assertIsNone(parsed_data['ip'])
        self.assertIsNone(parsed_data['error'])


    def test_summary_stats_collector(self):
        collector = SummaryStatsCollector()
        ts1 = datetime.datetime(2023,1,1,10,0,0, tzinfo=datetime.timezone.utc)
        ts2 = datetime.datetime(2023,1,1,10,0,10, tzinfo=datetime.timezone.utc)
        collector.process_packet(ts1, 100, "Ethernet")
        collector.process_packet(ts2, 150, "Ethernet")
        results = collector.get_results()
        self.assertEqual(results['total_packets'], 2)

    def test_ip_usage_collector(self):
        collector = IpUsageCollector()
        parsed_data_1 = {'ip': {'version':4, 'src_ip_bytes': socket.inet_aton("1.1.1.1"), 'dst_ip_bytes': socket.inet_aton("2.2.2.2"), 'src_ip_str':'1.1.1.1', 'dst_ip_str':'2.2.2.2'}}
        collector.process_packet(parsed_data_1)
        results = collector.get_results(top_n=1)
        self.assertEqual(results['top_src_ips'], [("1.1.1.1", 1)])

    @patch('pcap_analyzer.ReportGenerator._write_csv')
    @patch('builtins.print')
    def test_internal_report_generator_csv_calls(self, mock_print, mock_write_csv_method):
        args = argparse.Namespace(output_dir="test_out", ip_top_n=1, dns_top_n=1, http_top_n=1, tls_top_n=1, conv_top_n=1, verbose=False)
        report_gen = ReportGenerator(args)
        all_results = {
            'summary_stats': {}, 'proto_dist': {}, 'ip_usage': {'top_src_ips':[],'top_dst_ips':[]},
            'conversations': [], 'dns_analysis': {'query_log':[],'top_queries':[]},
            'http_analysis': {'requests':[],'top_hosts':[]}, 'tls_analysis': {'client_hellos_sni':[],'top_sni':[]}
        }
        report_gen.generate_csv_outputs(all_results)
        self.assertTrue(mock_write_csv_method.called)
        self.assertTrue(any(call_args[0][0] == "summary_stats.csv" for call_args in mock_write_csv_method.call_args_list))


if __name__ == '__main__':
    unittest.main()

[end of test_pcap_analyzer.py]
