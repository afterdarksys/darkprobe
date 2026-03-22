# This plugin automatically flags protocol parser failures (malformed headers or exploit attempts)

def process_packet(pkt):
    pass # ignoring regular packets

def on_malformed_packet(pkt, error_reason):
    print("================[ MALFORMED PACKET DETECTED ]=================")
    print("Source IP:   " + pkt.get("ip", "unknown"))
    print("Source MAC:  " + pkt.get("mac", "unknown"))
    print("Parser Err:  " + error_reason)
    
    if "DNS" in error_reason:
        print(">>> CRITICAL ALERT: Malformed DNS packet. Potential cache-poisoning or IDS evasion!")
    elif "IPv4" in error_reason:
        print(">>> ALERT: IPv4 Extension Header mutation detected. Evading Firewalls?")

    print("--------------------------------------------------------------")
