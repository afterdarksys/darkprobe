# This is a Starlark script that gets evaluated for every packet payload!
# Load this with: sudo ./darkprobe sniff --interface eth0 --script ./test_script.star

def process_packet(pkt):
    print("----- programmable packet hook fired -----")
    print("IP Address:  " + pkt["ip"])
    print("MAC Address: " + pkt.get("mac", "unknown"))
    
    if pkt.get("os"):
        print("Guessed OS:  " + pkt["os"])
        
    protos = pkt.get("protocols", [])
    if len(protos) > 0:
        print("Protocols:   " + ", ".join(protos))
        
        # Threat Hunting example logic
        if "802.1X (EAPOL)" in protos:
            print(">>> ALERT: EAPOL Auth Handshake Captured from " + pkt["mac"])
            
    hostnames = pkt.get("hostnames", [])
    if len(hostnames) > 0:
        print("Hostnames:   " + ", ".join(hostnames))
        
    print("------------------------------------------")
