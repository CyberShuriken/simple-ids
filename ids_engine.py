import scapy.all as scapy
import re
import threading
import time
from datetime import datetime

class IDSEngine:
    def __init__(self, rule_file="local.rules"):
        self.rules = []
        self.alerts = []
        self.rule_file = rule_file
        self.running = True
        self.lock = threading.Lock()
        
        self.load_rules()

    def load_rules(self):
        """
        Parses the local.rules file.
        Supports basic syntax: alert proto src sport -> dst dport (msg:"...";)
        """
        print(f"Loading rules from {self.rule_file}...")
        self.rules = []
        try:
            with open(self.rule_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Regex to parse rule parts
                    # Example: alert tcp any any -> any 80 (msg:"HTTP";)
                    pattern = r'^(?P<action>\w+) (?P<proto>\w+) (?P<src>\S+) (?P<sport>\S+) -> (?P<dst>\S+) (?P<dport>\S+) \((?P<options>.*)\)'
                    match = re.match(pattern, line)
                    
                    if match:
                        rule = match.groupdict()
                        # Parse options (msg, sid)
                        options = {}
                        for opt in rule['options'].split(';'):
                            if ':' in opt:
                                key, val = opt.split(':', 1)
                                options[key.strip()] = val.strip().strip('"')
                        
                        rule['msg'] = options.get('msg', 'Unknown Alert')
                        rule['sid'] = options.get('sid', '0')
                        self.rules.append(rule)
                        print(f"Loaded Rule: {rule['msg']}")
        except FileNotFoundError:
            print("Rule file not found!")

    def match_packet(self, packet):
        """
        Checks if a packet matches any loaded rule.
        """
        # Debug: Print every 10th packet to confirm sniffing works
        # if packet.haslayer(scapy.IP):
        #     print(f"[DEBUG] Inspecting packet: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}")

        for rule in self.rules:
            # 1. Check Protocol
            proto_match = False
            if rule['proto'] == 'icmp' and packet.haslayer(scapy.ICMP):
                proto_match = True
            elif rule['proto'] == 'tcp' and packet.haslayer(scapy.TCP):
                proto_match = True
            elif rule['proto'] == 'udp' and packet.haslayer(scapy.UDP):
                proto_match = True
            elif rule['proto'] == 'ip' and packet.haslayer(scapy.IP):
                proto_match = True
            
            if not proto_match:
                continue

            # 2. Check IP (Source/Dest)
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Simple 'any' check (ignoring CIDR for this demo)
                if rule['src'] != 'any' and rule['src'] != src_ip:
                    continue
                if rule['dst'] != 'any' and rule['dst'] != dst_ip:
                    continue
            
            # 3. Check Port (TCP/UDP)
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                sport = packet.sport
                dport = packet.dport
                
                # Debug: Check if we are seeing the ports we expect
                if str(dport) == "4444" or str(dport) == "80":
                     print(f"[DEBUG] Potential match on port {dport}")

                if rule['sport'] != 'any' and str(rule['sport']) != str(sport):
                    continue
                if rule['dport'] != 'any' and str(rule['dport']) != str(dport):
                    continue

            # MATCH FOUND
            print(f"[MATCH] Rule triggered: {rule['msg']}")
            self.trigger_alert(rule, packet)

    def trigger_alert(self, rule, packet):
        with self.lock:
            src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown"
            dst = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "Unknown"
            
            alert = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "sid": rule['sid'],
                "msg": rule['msg'],
                "src": src,
                "dst": dst,
                "proto": rule['proto'].upper()
            }
            
            # Dedup: Don't spam the same alert instantly
            if not self.alerts or (self.alerts[0]['msg'] != alert['msg'] or self.alerts[0]['src'] != alert['src']):
                print(f"[ALERT] {alert['msg']} from {src}")
                self.alerts.insert(0, alert)
                if len(self.alerts) > 50:
                    self.alerts.pop()

    def start(self):
        t = threading.Thread(target=self.sniff)
        t.daemon = True
        t.start()

    def sniff(self):
        print("Sniffer started...")
        scapy.sniff(prn=self.match_packet, store=False)

    def get_alerts(self):
        with self.lock:
            return self.alerts
