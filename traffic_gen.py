import scapy.all as scapy
import time
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def generate_traffic():
    target = get_local_ip()
    print(f"Generating traffic to {target}...")

    # 1. Ping (ICMP)
    print("Sending Ping (ICMP)...")
    scapy.send(scapy.IP(dst=target)/scapy.ICMP(), verbose=False)
    time.sleep(1)

    # 2. HTTP (TCP Port 80)
    print("Sending HTTP Request (TCP 80)...")
    scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=80), verbose=False)
    time.sleep(1)

    # 3. Suspicious (TCP Port 4444)
    print("Sending Suspicious Packet (TCP 4444)...")
    scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=4444), verbose=False)
    
    print("Traffic generation complete.")

if __name__ == "__main__":
    generate_traffic()
