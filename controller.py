#!/usr/bin/env python3
import sys
import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw

def handle_pkt(pkt):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_msg = f"[{timestamp}] "

    if pkt.haslayer(IP):
        ip = pkt[IP]
        log_msg += f"{ip.src} -> {ip.dst} "
    else:
        print(f"[{timestamp}] Non-IP Packet: {pkt.summary()}")
        return

    if pkt.haslayer(TCP):
        transport = pkt[TCP]
        log_msg += f"TCP {transport.sport} -> {transport.dport} "
    elif pkt.haslayer(UDP):
        transport = pkt[UDP]
        log_msg += f"UDP {transport.sport} -> {transport.dport} "
    else:
        log_msg += "Other-Transport "

    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        hex_payload = payload.hex()
        if len(hex_payload) > 64:
            hex_payload = hex_payload[:64] + "..."
        log_msg += f"| Payload: {hex_payload}"

    print(log_msg)
    sys.stdout.flush()

def main():
    if len(sys.argv) < 2:
        # Default to the CPU port interface of the IDS switch
        iface = 's1-cpu-eth0'
    else:
        iface = sys.argv[1]

    print(f'[+] Starting IDS Monitor on interface: {iface}')
    print(f'[+] Listening for malicious packets...')
    sys.stdout.flush()

    try:
        sniff(iface=iface, prn=handle_pkt, store=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping monitor.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
