# App Identifier Plugin
# Detects the use of specific high-profile applications on the network based on passive metadata

def process_packet(pkt):
    hostnames = pkt.get("hostnames", [])
    
    for host in hostnames:
        # 1. Signal & Secure Messengers
        if "signal.org" in host or "whispersystems" in host:
            print(">>> [APP DETECTION] Signal Secure Messenger used by: " + pkt["ip"])
        
        # 2. WhatsApp & Meta Messengers
        elif "whatsapp.net" in host or "whatsapp.com" in host:
            print(">>> [APP DETECTION] WhatsApp Messenger used by: " + pkt["ip"])
            
        # 3. Telegram
        elif "telegram.org" in host:
            print(">>> [APP DETECTION] Telegram Messenger used by: " + pkt["ip"])
            
        # 4. File Sharing & P2P Protocols
        elif "torrent" in host or "tracker" in host or "bittorrent" in host:
            print(">>> [APP DETECTION] BitTorrent/P2P File Sharing used by: " + pkt["ip"])
            
        # 5. Cloud Storage syncs (often used for data exfiltration)
        elif "dropbox.com" in host or "api.dropbox" in host:
            print(">>> [APP DETECTION] Dropbox Sync initialized by: " + pkt["ip"])

def on_malformed_packet(pkt, error_reason):
    pass # Managed by the malformed_detector.star plugin
