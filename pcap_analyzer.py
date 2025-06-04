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

# --- PCAP Reader Class (assumed correct from previous step) ---
class PcapReader:
    def __init__(self, filepath, verbose=False):
        self.filepath = filepath; self.file_handle = None; self.reader = None
        self.linktype = None; self.is_pcapng = False
        try:
            self.file_handle = open(self.filepath, 'rb')
            try:
                self.reader = dpkt.pcapng.Reader(self.file_handle)
                self.is_pcapng = True; self.linktype = None
                with open(self.filepath, 'rb') as temp_f: # Temporary re-open to scan for IDB
                    temp_r = dpkt.pcapng.Reader(temp_f)
                    for blk_type, blk_body in temp_r:
                        if blk_type == dpkt.pcapng.PKT_IDB:
                            try: self.linktype = dpkt.pcapng.IDB(blk_body).linktype; break
                            except dpkt.dpkt.Error:
                                if verbose: print("Warning: Could not parse IDB in PCAPng for linktype.", file=sys.stderr)
                                break
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

# --- Packet Parser Class (assumed correct from previous step) ---
class PacketParser:
    def __init__(self): pass
    def parse_packet(self, timestamp_s, buf, linktype):
        parsed = {'timestamp': datetime.datetime.fromtimestamp(timestamp_s, tz=datetime.timezone.utc),
                  'linktype_str': 'Unknown', 'eth': None, 'ip': None, 'arp': None,
                  'transport_obj': None, 'payload': None, 'transport': None, 'app_layer': None,
                  'error': None, 'raw_buffer_len': len(buf)}
        ip_obj = None; ip_payload = None
        try:
            if linktype == dpkt.pcap.DLT_EN10MB:
                parsed['linktype_str'] = 'Ethernet'; eth = dpkt.ethernet.Ethernet(buf)
                parsed['eth'] = {'src_mac':format_mac(eth.src), 'dst_mac':format_mac(eth.dst), 'type':eth.type}
                if eth.type == dpkt.ethernet.ETH_TYPE_ARP: parsed['arp'] = dpkt.arp.ARP(eth.data)
                elif isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)): ip_obj = eth.data
            elif linktype == dpkt.pcap.DLT_LINUX_SLL:
                parsed['linktype_str'] = 'Linux SLL'; sll = dpkt.sll.SLL(buf)
                if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)): ip_obj = sll.data
            elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
                parsed['linktype_str'] = f'Loopback/Null({linktype})'; loop = dpkt.loopback.Loopback(buf)
                if isinstance(loop.data, (dpkt.ip.IP, dpkt.ip6.IP6)): ip_obj = loop.data
            elif linktype == dpkt.pcap.DLT_RAW:
                try: ip_obj = dpkt.ip.IP(buf); parsed['linktype_str'] = 'Raw IPv4'
                except (dpkt.dpkt.Error, AttributeError):
                    try: ip_obj = dpkt.ip6.IP6(buf); parsed['linktype_str'] = 'Raw IPv6'
                    except (dpkt.dpkt.Error, AttributeError): parsed['error'] = "DLT_RAW: Not IPv4/IPv6"
            else: parsed['error'] = f"Unsupported linktype: {linktype}"

            if ip_obj:
                ver = getattr(ip_obj, 'v', 0); src_b = getattr(ip_obj,'src',b''); dst_b = getattr(ip_obj,'dst',b''); proto = 0; ip_len = 0
                if ver == 4 and isinstance(ip_obj, dpkt.ip.IP):
                    proto=ip_obj.p; ip_payload=ip_obj.data; ip_len=ip_obj.len
                    parsed['ip']={'src_ip_bytes':src_b,'dst_ip_bytes':dst_b,'proto':proto,'version':4,'len':ip_len,'src_ip_str':socket.inet_ntoa(src_b),'dst_ip_str':socket.inet_ntoa(dst_b)}
                elif ver == 6 and isinstance(ip_obj, dpkt.ip6.IP6):
                    proto=ip_obj.nxt; ip_payload=ip_obj.data; ip_len=ip_obj.plen+40 # plen is payload, add header size
                    parsed['ip']={'src_ip_bytes':src_b,'dst_ip_bytes':dst_b,'proto':proto,'version':6,'len':ip_len,'src_ip_str':socket.inet_ntop(socket.AF_INET6,src_b),'dst_ip_str':socket.inet_ntop(socket.AF_INET6,dst_b)}
                if ip_payload:
                    parsed['transport_obj']=ip_payload
                    if proto==dpkt.ip.IP_PROTO_TCP and isinstance(ip_payload,dpkt.tcp.TCP):
                        tcp=ip_payload;parsed['transport']={'type':'TCP','src_port':tcp.sport,'dst_port':tcp.dport,'flags':tcp.flags};parsed['payload']=tcp.data
                        if tcp.sport==80 or tcp.dport==80:
                            try:parsed['app_layer']={'type':'HTTP','data_obj':dpkt.http.Request(tcp.data)}
                            except(dpkt.dpkt.Error,AttributeError):
                                try:parsed['app_layer']={'type':'HTTP','data_obj':dpkt.http.Response(tcp.data)}
                                except(dpkt.dpkt.Error,AttributeError):pass
                        elif tcp.sport==443 or tcp.dport==443:
                            if len(tcp.data)>0:
                                try:parsed['app_layer']={'type':'TLS','data_obj':dpkt.ssl.TLS(tcp.data)}
                                except(dpkt.dpkt.Error,AttributeError):pass
                    elif proto==dpkt.ip.IP_PROTO_UDP and isinstance(ip_payload,dpkt.udp.UDP):
                        udp=ip_payload;parsed['transport']={'type':'UDP','src_port':udp.sport,'dst_port':udp.dport};parsed['payload']=udp.data
                        if udp.sport==53 or udp.dport==53:
                            try:parsed['app_layer']={'type':'DNS','data_obj':dpkt.dns.DNS(udp.data)}
                            except(dpkt.dpkt.Error,AttributeError):pass
                    elif proto==dpkt.ip.IP_PROTO_ICMP and isinstance(ip_payload,dpkt.icmp.ICMP):
                        icmp=ip_payload;parsed['transport']={'type':'ICMP','icmp_type':icmp.type,'icmp_code':icmp.code};parsed['payload']=icmp.data.data
                    elif proto==dpkt.ip.IP_PROTO_ICMPV6 and isinstance(ip_payload,dpkt.icmp6.ICMP6):
                        icmp6=ip_payload;parsed['transport']={'type':'ICMPv6','icmp_type':icmp6.type,'icmp_code':icmp6.code};parsed['payload']=icmp6.data.data
        except dpkt.dpkt.Error as e: parsed['error']=f"DPKT Error: {e}"
        except Exception as e: parsed['error']=f"Generic parsing error: {e} ({type(e).__name__})"
        return parsed

# --- Collector Classes (assumed correct from previous steps) ---
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
    def _get_canonical_key(self,ip_s_b,ip_d_b,p,sp,dp): return tuple(sorted(((ip_s_b,sp),(ip_d_b,dp))))+(p,)
    def process_packet(self,pdata):
        if pdata.get('ip') and pdata.get('transport') and pdata['transport']['type'] in ['TCP','UDP']:
            ip_i=pdata['ip']; tr_i=pdata['transport']; pkt_l=ip_i.get('len',pdata.get('raw_buffer_len',0))
            k=self._get_canonical_key(ip_i['src_ip_bytes'],ip_i['dst_ip_bytes'],ip_i['proto'],tr_i['src_port'],tr_i['dst_port'])
            conv=self.conversations.setdefault(k,{'ip1_b':k[0][0],'port1':k[0][1],'ip2_b':k[1][0],'port2':k[1][1],'proto':k[2],'pkts12':0,'bytes12':0,'pkts21':0,'bytes21':0,'first_ts':pdata['timestamp'],'last_ts':pdata['timestamp'],'tcp_flags':collections.Counter() if tr_i['type']=='TCP' else None})
            if (ip_i['src_ip_bytes'],tr_i['src_port'])==(conv['ip1_b'],conv['port1']): conv['pkts12']+=1; conv['bytes12']+=pkt_l
            else: conv['pkts21']+=1; conv['bytes21']+=pkt_l
            conv['last_ts']=max(conv['last_ts'],pdata['timestamp'])
            if tr_i['type']=='TCP' and conv['tcp_flags'] is not None:
                f=tr_i.get('flags',0); tc=conv['tcp_flags']
                if f&dpkt.tcp.TH_SYN: tc['SYN']+=1;
                if f&dpkt.tcp.TH_FIN: tc['FIN']+=1
                if f&dpkt.tcp.TH_RST: tc['RST']+=1
                if f&dpkt.tcp.TH_ACK: tc['ACK']+=1 # Count all ACKs
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
        res.sort(key=lambda x:x.get(sort_by,0),reverse=rev) # Use .get for sort_by robustness
        return res[:top_n] if top_n else res
class DnsAnalyzer:
    def __init__(self): self.queries=collections.Counter(); self.responses={}; self.query_log=[]
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='DNS' and pdata['app_layer']['data_obj']:
            dns = pdata['app_layer']['data_obj']
            if not isinstance(dns, dpkt.dns.DNS): return
            ts = pdata['timestamp']
            if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                for q in dns.qd: self.queries[q.name]+=1; self.query_log.append({'ts':ts,'id':dns.id,'name':q.name,'qtype':q.type}) # Renamed 'type' to 'qtype'
            elif dns.qr == dpkt.dns.DNS_R and dns.an:
                ans=[]
                for rr in dns.an:
                    val=None
                    if rr.type==dpkt.dns.DNS_A and hasattr(rr,'ip'): val=socket.inet_ntoa(rr.ip)
                    elif rr.type==dpkt.dns.DNS_AAAA and hasattr(rr,'ip6'): val=socket.inet_ntop(socket.AF_INET6,rr.ip6)
                    elif rr.type==dpkt.dns.DNS_CNAME and hasattr(rr,'cname'): val=rr.cname.decode('utf-8','ignore') if isinstance(rr.cname, bytes) else rr.cname
                    elif rr.type==dpkt.dns.DNS_PTR and hasattr(rr,'ptrname'): val=rr.ptrname.decode('utf-8','ignore') if isinstance(rr.ptrname, bytes) else rr.ptrname
                    elif rr.type==dpkt.dns.DNS_MX and hasattr(rr,'mxname'): val=rr.mxname.decode('utf-8','ignore') if isinstance(rr.mxname, bytes) else rr.mxname
                    elif rr.type==dpkt.dns.DNS_NS and hasattr(rr,'nsname'): val=rr.nsname.decode('utf-8','ignore') if isinstance(rr.nsname, bytes) else rr.nsname
                    elif rr.type==dpkt.dns.DNS_SOA and hasattr(rr,'mname'): val=rr.mname.decode('utf-8','ignore') if isinstance(rr.mname, bytes) else rr.mname
                    else: val = "Other/Data"
                    ans.append({'name':rr.name,'atype':rr.type,'val':val,'ttl':rr.ttl}) # Renamed 'type' to 'atype'
                if ans: self.responses.setdefault(dns.id,[]).append({'ts':ts,'answers':ans})
    def get_results(self,top_n=10): return {'top_queries':self.queries.most_common(top_n),'query_log':self.query_log,'responses':self.responses}
class HttpAnalyzer:
    def __init__(self): self.requests=[]; self.host_counts=collections.Counter()
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='HTTP' and pdata['app_layer']['data_obj']:
            http = pdata['app_layer']['data_obj']
            if isinstance(http, dpkt.http.Request):
                host = http.headers.get('host','N/A')
                self.requests.append({'ts':pdata['timestamp'],'method':http.method,'uri':http.uri,'ver':http.version,'host':host,'ua':http.headers.get('user-agent','N/A'), 'src_ip': pdata.get('ip',{}).get('src_ip_str','N/A'), 'dst_ip': pdata.get('ip',{}).get('dst_ip_str','N/A')})
                if host!='N/A': self.host_counts[host]+=1
    def get_results(self,top_n=10): return {'requests':self.requests[-top_n*20:], 'top_hosts':self.host_counts.most_common(top_n)}
class TlsAnalyzer:
    def __init__(self): self.client_hellos_sni=[]; self.sni_counts=collections.Counter()
    def _parse_tls_sni(self, extensions_bytes_or_list):
        if not extensions_bytes_or_list: return None
        try:
            if isinstance(extensions_bytes_or_list, list): # dpkt already parsed TLSExtension objects
                for ext_obj in extensions_bytes_or_list:
                    if hasattr(ext_obj, 'type') and ext_obj.type == dpkt.ssl.TLSEXT_SERVER_NAME:
                        if hasattr(ext_obj, 'data') and isinstance(ext_obj.data, bytes):
                            try:
                                sni_list = dpkt.ssl.TLSServerName(ext_obj.data)
                                if sni_list.server_names:
                                     for sn in sni_list.server_names:
                                        if sn.type == dpkt.ssl.TLS_SERVER_NAME_HOSTNAME: return sn.name.decode('utf-8', 'ignore')
                            except dpkt.dpkt.Error: continue
                        elif hasattr(ext_obj, 'data') and isinstance(ext_obj.data, dpkt.ssl.TLSServerName):
                             if ext_obj.data.server_names:
                                for sn in ext_obj.data.server_names:
                                    if sn.type == dpkt.ssl.TLS_SERVER_NAME_HOSTNAME: return sn.name.decode('utf-8', 'ignore')
                return None
            if isinstance(extensions_bytes_or_list, bytes): # Raw bytes for extensions
                idx = 0; ext_bytes = extensions_bytes_or_list
                if len(ext_bytes) < 2: return None
                total_ext_len = int.from_bytes(ext_bytes[idx:idx+2],byteorder='big'); idx+=2
                parsed_len=0
                while parsed_len < total_ext_len and idx+4 <= len(ext_bytes):
                    ext_type=int.from_bytes(ext_bytes[idx:idx+2],byteorder='big'); idx+=2
                    ext_len=int.from_bytes(ext_bytes[idx:idx+2],byteorder='big'); idx+=2
                    if ext_type == dpkt.ssl.TLSEXT_SERVER_NAME:
                        if idx+ext_len > len(ext_bytes) or ext_len < 2: break
                        sni_list_len=int.from_bytes(ext_bytes[idx:idx+2],byteorder='big'); idx_sni=idx+2
                        parsed_sni_list_len=0
                        while parsed_sni_list_len < sni_list_len and idx_sni+3 <= len(ext_bytes):
                            name_type=ext_bytes[idx_sni]; idx_sni+=1
                            name_len=int.from_bytes(ext_bytes[idx_sni:idx_sni+2],byteorder='big'); idx_sni+=2
                            if name_type == dpkt.ssl.TLS_SERVER_NAME_HOSTNAME:
                                if idx_sni+name_len <= len(ext_bytes): return ext_bytes[idx_sni:idx_sni+name_len].decode('utf-8','ignore')
                                else: break
                            idx_sni+=name_len; parsed_sni_list_len=idx_sni-(idx+2)
                        break
                    idx+=ext_len; parsed_len=idx-2
        except Exception: return None
        return None
    def process_packet(self, pdata):
        if pdata.get('app_layer',{}).get('type')=='TLS' and pdata['app_layer']['data_obj']:
            tls_record = pdata['app_layer']['data_obj']
            if not isinstance(tls_record, dpkt.ssl.TLS): return
            if hasattr(tls_record, 'data') and isinstance(tls_record.data, bytes) and tls_record.type == dpkt.ssl.TLS_HANDSHAKE:
                try:
                    handshake_msgs = dpkt.ssl.TLSHandshake(tls_record.data)
                    if not isinstance(handshake_msgs, list): handshake_msgs = [handshake_msgs]
                    for msg in handshake_msgs:
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
import csv # Ensure csv is imported for ReportGenerator
class ReportGenerator:
    def __init__(self, args):
        self.args = args
        self.output_dir = os.path.abspath(args.output_dir) if args.output_dir else None
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)

    def _format_timestamp(self, dt_obj):
        return dt_obj.isoformat() if dt_obj else 'N/A'

    def _format_flags(self, flags_counter):
        if not flags_counter: return ""
        return ",".join([f"{flag}:{count}" for flag, count in flags_counter.items()])

    def _write_csv(self, filename, headers, rows_data):
        if not self.output_dir:
            if self.args.verbose: print(f"Skipping CSV '{filename}' because no output directory is set.", file=sys.stderr)
            return False
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for row in rows_data:
                    writer.writerow([str(col) if col is not None else "" for col in row])
            if self.args.verbose: print(f"Successfully wrote CSV: {filepath}", file=sys.stderr)
            return True
        except IOError as e:
            print(f"Error writing CSV file {filepath}: {e}", file=sys.stderr)
            return False

    def print_console_summary(self, all_results):
        print("\n--- Summary Statistics ---")
        for k,v in all_results['summary_stats'].items(): print(f"  {k.replace('_',' ').title()}: {v}")

        print("\n--- Protocol Distribution ---")
        for cat, data in all_results['proto_dist'].items():
            print(f"  {cat.replace('_',' ').title()}:")
            if data:
                for p,c in sorted(data.items(),key=lambda x:x[1],reverse=True): print(f"    {p}: {c}")
            else: print("    (No data)")

        ip_usage = all_results['ip_usage']
        print(f"\n--- Top {self.args.ip_top_n} Source IPs ---")
        for ip,c in ip_usage['top_src_ips'][:self.args.ip_top_n]: print(f"  {ip}: {c}")
        print(f"\n--- Top {self.args.ip_top_n} Destination IPs ---")
        for ip,c in ip_usage['top_dst_ips'][:self.args.ip_top_n]: print(f"  {ip}: {c}")

        convs = all_results['conversations']
        print(f"\n--- Top {self.args.conv_top_n} Conversations (by total packets) ---")
        for i,c in enumerate(convs[:self.args.conv_top_n]):
            print(f"  {i+1}. {c['ip1_s']}:{c['port1']} <-> {c['ip2_s']}:{c['port2']} (Proto: {c['proto']})")
            print(f"     Pkts: {c['total_pkts']} (1->2: {c['pkts12']}, 2->1: {c['pkts21']}) Bytes: {c['total_bytes']} Dur: {c['duration_s']:.3f}s")
            if c['tcp_flags']: print(f"     TCP Flags: {self._format_flags(c['tcp_flags'])}")

        dns_res = all_results['dns_analysis']
        print(f"\n--- Top {self.args.dns_top_n} DNS Queried Names ---")
        for name,c in dns_res['top_queries'][:self.args.dns_top_n]: print(f"  {name}: {c}")
        if self.args.verbose and dns_res['query_log']:
            print("  Last 5 DNS Queries Logged:")
            for q in dns_res['query_log'][-5:]: print(f"    {self._format_timestamp(q['ts'])} ID:{q['id']} Name:{q['name']} Type:{q['qtype']}")

        http_res = all_results['http_analysis']
        print(f"\n--- Top {self.args.http_top_n} HTTP Hosts ---")
        for host,c in http_res['top_hosts'][:self.args.http_top_n]: print(f"  {host}: {c}")
        if self.args.verbose and http_res['requests']:
            print("  Last 5 HTTP Requests Logged:")
            for r in http_res['requests'][-5:]: print(f"    {self._format_timestamp(r['ts'])} {r['method']} {r['host']}{r['uri']}")

        tls_res = all_results['tls_analysis']
        print(f"\n--- Top {self.args.tls_top_n} TLS SNI Hostnames ---")
        for sni,c in tls_res['top_sni'][:self.args.tls_top_n]: print(f"  {sni}: {c}")
        if self.args.verbose and tls_res['client_hellos_sni']:
            print("  Last 5 TLS Client Hellos with SNI Logged:")
            for h in tls_res['client_hellos_sni'][-5:]: print(f"    {self._format_timestamp(h['ts'])} SNI: {h['sni']} (Src: {h['src']}, Dst: {h['dst']})")


    def generate_csv_outputs(self, all_results):
        if not self.output_dir: return

        # Summary Stats
        ss = all_results['summary_stats']
        self._write_csv("summary_stats.csv", ["Statistic", "Value"], list(ss.items()))

        # Protocol Distribution
        pd_rows = []
        for cat, data in all_results['proto_dist'].items():
            for proto, count in data.items(): pd_rows.append([cat, proto, count])
        self._write_csv("protocol_distribution.csv", ["Category", "Protocol", "Count"], pd_rows)

        # IP Usage
        self._write_csv("ip_source_summary.csv", ["IP_Address", "Packet_Count"], all_results['ip_usage']['top_src_ips'])
        self._write_csv("ip_destination_summary.csv", ["IP_Address", "Packet_Count"], all_results['ip_usage']['top_dst_ips'])

        # Conversations
        conv_headers = ["Src_IP", "Dst_IP", "Src_Port", "Dst_Port", "Protocol",
                        "Packets_1to2", "Bytes_1to2", "Packets_2to1", "Bytes_2to1",
                        "First_Seen_UTC", "Last_Seen_UTC", "Duration_sec", "TCP_Flags"]
        conv_rows = [[c['ip1_s'],c['ip2_s'],c['port1'],c['port2'],c['proto'],c['pkts12'],c['bytes12'],
                      c['pkts21'],c['bytes21'], self._format_timestamp(c['first_ts']),
                      self._format_timestamp(c['last_ts']), c['duration_s'],
                      self._format_flags(c['tcp_flags']) if c['tcp_flags'] else "N/A"] for c in all_results['conversations']]
        self._write_csv("conversations.csv", conv_headers, conv_rows)

        # DNS
        dns_q_headers = ["Timestamp_UTC", "Query_ID", "Query_Name", "Query_Type"]
        dns_q_rows = [[self._format_timestamp(q['ts']), q['id'], q['name'], q['qtype']] for q in all_results['dns_analysis']['query_log']]
        self._write_csv("dns_queries.csv", dns_q_headers, dns_q_rows)
        self._write_csv("dns_top_queried_names.csv", ["Queried_Name", "Count"], all_results['dns_analysis']['top_queries'])
        # DNS Responses CSV would be more complex due to nested structure, skipping for now.

        # HTTP
        http_headers = ["Timestamp_UTC", "Src_IP", "Dst_IP", "Method", "Host", "URI", "User_Agent", "Version"]
        http_rows = [[self._format_timestamp(r['ts']), r['src_ip'], r['dst_ip'], r['method'], r['host'], r['uri'], r['ua'], r['ver']] for r in all_results['http_analysis']['requests']]
        self._write_csv("http_requests.csv", http_headers, http_rows)
        self._write_csv("http_top_hosts.csv", ["Host", "Count"], all_results['http_analysis']['top_hosts'])

        # TLS
        tls_headers = ["Timestamp_UTC", "Src_IP", "Dst_IP", "SNI_Hostname"]
        tls_rows = [[self._format_timestamp(h['ts']), h['src'], h['dst'], h['sni']] for h in all_results['tls_analysis']['client_hellos_sni']]
        self._write_csv("tls_client_hellos_sni.csv", tls_headers, tls_rows)
        self._write_csv("tls_top_sni.csv", ["SNI_Hostname", "Count"], all_results['tls_analysis']['top_sni'])


# --- Main ---
if __name__ == '__main__':
    args = setup_parser().parse_args()
    if not os.path.exists(args.pcap_file): print(f"Error: PCAP file '{args.pcap_file}' not found.", file=sys.stderr); sys.exit(1)

    collectors = [SummaryStatsCollector(), ProtocolDistributionCollector(), IpUsageCollector(), ConversationTracker(), DnsAnalyzer(), HttpAnalyzer(), TlsAnalyzer()]

    try:
        pcap_reader = PcapReader(args.pcap_file, verbose=args.verbose)
        packet_parser = PacketParser()
        if args.verbose: print(f"Opened PCAP: {args.pcap_file}, Linktype: {pcap_reader.linktype}")

        pkt_limit = 50 if not args.verbose else float('inf') # Increased limit for better summary with default run
        processed_count = 0
        for i, (ts, buf) in enumerate(pcap_reader):
            processed_count = i + 1
            if i >= pkt_limit and not args.verbose :
                print(f"\nProcessed first {pkt_limit} packets. Use --verbose to see all individual packet details and full processing.")
                break
            parsed = packet_parser.parse_packet(ts, buf, pcap_reader.linktype)
            for collector in collectors: collector.process_packet(parsed)

            if args.verbose : # Only print per-packet details if verbose
                print(f"\n--- Pkt {i+1} ---")
                print(f"  Timestamp: {parsed['timestamp'].isoformat()}")
                if parsed['eth']: print(f"  Ethernet: Src MAC: {parsed['eth']['src_mac']}, Dst MAC: {parsed['eth']['dst_mac']}, Type: {hex(parsed['eth']['type'])}")
                if parsed['ip']:
                    src_ip_str = parsed['ip']['src_ip_str']; dst_ip_str = parsed['ip']['dst_ip_str']
                    print(f"  IP: Version: {parsed['ip']['version']}, Src IP: {src_ip_str}, Dst IP: {dst_ip_str}, Protocol: {parsed['ip']['proto']}")
                if parsed['transport']:
                    trans = parsed['transport']
                    print(f"  Transport ({trans['type']}): Src Port: {trans.get('src_port', 'N/A')}, Dst Port: {trans.get('dst_port', 'N/A')}")
                if parsed['app_layer']: print(f"  App Layer: Type: {parsed['app_layer']['type']}")
                if parsed['error']: print(f"  Error: {parsed['error']}")

        pcap_reader.close()
        if not args.verbose and processed_count > pkt_limit : print(f"\nProcessed {processed_count} total packets.")
        elif args.verbose : print(f"\nProcessed {processed_count} total packets.")


        all_results = {
            'summary_stats': collectors[0].get_results(),
            'proto_dist': collectors[1].get_results(),
            'ip_usage': collectors[2].get_results(top_n=None), # Get all for CSV
            'conversations': collectors[3].get_results(top_n=None, sort_by='total_packets'), # Get all for CSV
            'dns_analysis': collectors[4].get_results(top_n_queries=None),
            'http_analysis': collectors[5].get_results(top_n_hosts=None),
            'tls_analysis': collectors[6].get_results(top_n_sni=None)
        }

        report_gen = ReportGenerator(args)
        report_gen.print_console_summary(all_results)
        report_gen.generate_csv_outputs(all_results)

    except (IOError, ValueError, dpkt.dpkt.Error) as e: print(f"Error: {e}", file=sys.stderr); sys.exit(1)
    except Exception as e: print(f"An unexpected error occurred: {e}", file=sys.stderr); sys.exit(1)
    print("\nPCAP analysis finished.")
