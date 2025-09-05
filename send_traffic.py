from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, UDP, Raw
import sys, socket, time

def get_if():
    ifs=get_if_list()
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    exit(1)

def send_packet(dst_mac, dst_ip, dport, sport, protocol, payload, iface):
    # Build the Ethernet and IP headers
    pkt = Ether(dst=dst_mac, src=get_if_hwaddr(iface)) / IP(dst=dst_ip)
    
    # Add the Transport layer header (TCP or UDP)
    if protocol.upper() == 'TCP':
        pkt = pkt / TCP(dport=dport, sport=sport)
    elif protocol.upper() == 'UDP':
        pkt = pkt / UDP(dport=dport, sport=sport)
    else:
        print(f"Unsupported protocol: {protocol}")
        return
        
    # Add the payload and send the packet
    pkt = pkt / Raw(load=payload)
    sendp(pkt, iface=iface, verbose=False)
    print(f"Sent {protocol} packet to {dst_ip}:{dport} with payload: {payload.hex()}")
    time.sleep(0.1) # Small delay to avoid overwhelming the interface

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send_traffic.py <dst_ip>")
        sys.exit(1)

    dst_ip = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    h2_mac = '00:00:0a:00:02:02' # MAC address of host h2

    test_flows = [
        # Flow 1 - TCP:1025
        ['TCP', 1025, 1080, [b'\x04\x04\x04\x04', b'\x04\x71\x04\x71', b'\x04\x04\x04\x04']],
        # Flow 2 - TCP:9999
        ['TCP', 9999, 1080, [b'\x03\x71\x03\x71', b'\xaa\xaa\xaa\xaa']],
        # Flow 3 - TCP:9786
        ['TCP', 9786, 1080, [b'\x03\x71\x03\x71']],
        # Flow 4 - UDP:53 (DNS-like)
        ['UDP', 53, 54000, [b'\x04\x04\x04\x04', b'\x04\x71\x04\x71', b'\xde\xad\xbe\xef']]
    ]

    print(f"[+] Sending test traffic from {get_if_hwaddr(iface)} to {dst_ip}")
    
    for protocol, dport, sport, payloads in test_flows:
        print(f"\n--- Testing {protocol} Flow (dport: {dport}) ---")
        for payload in payloads:
            send_packet(h2_mac, dst_ip, dport, sport, protocol, payload, iface)

    print("\n[+] Traffic injection complete.")
