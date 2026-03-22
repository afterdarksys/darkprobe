package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PassiveHost tracks passively discovered information
type PassiveHost struct {
	IP          string   `json:"ip"`
	MAC         string   `json:"mac,omitempty"`
	InferredOS  string   `json:"os,omitempty"`
	L7Protocols []string `json:"l7_protocols,omitempty"`
	Hostnames   []string `json:"hostnames,omitempty"` // from reverse DNS or TLS SNI/HTTP Host
}

type PassiveScanner struct {
	hosts          map[string]*PassiveHost
	neighbors      []NeighborInfo
	// Routing protocol data
	ripInfos       []RIPInfo
	bgpPeers       []BGPInfo
	ospfNeighbors  []OSPFInfo
	mu             sync.Mutex
	starlarkEngine *StarlarkEngine
	wpaDecrypter   *WPADecrypter
}

func (ps *PassiveScanner) EnableWPA2Decryption(ssid, passphrase string) error {
	ps.wpaDecrypter = NewWPADecrypter(ssid, passphrase)
	return nil
}

func NewPassiveScanner(engine *StarlarkEngine) *PassiveScanner {
	return &PassiveScanner{
		hosts:          make(map[string]*PassiveHost),
		neighbors:      []NeighborInfo{},
		// initialize routing slices
		ripInfos:      []RIPInfo{},
		bgpPeers:       []BGPInfo{},
		ospfNeighbors:  []OSPFInfo{},
		starlarkEngine: engine,
	}
}

// SniffNetwork listens on the interface for the given duration and returns discovered hosts
func (ps *PassiveScanner) SniffNetwork(ctx context.Context, iface string, duration time.Duration, monitorMode bool) ([]PassiveHost, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("could not create inactive handle: %v", err)
	}
	defer inactive.CleanUp()

	if monitorMode {
		err = inactive.SetRFMon(true)
		if err != nil {
			log.Printf("Warning: failed to set monitor mode: %v", err)
		}
	}

	err = inactive.SetSnapLen(1600)
	if err != nil {
		return nil, err
	}

	err = inactive.SetPromisc(true)
	if err != nil {
		return nil, err
	}

	err = inactive.SetTimeout(pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap on %s: %w", iface, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	log.Printf("Listening passively on %s for %v...", iface, duration)

	timeout := time.After(duration)
	
	for {
		select {
		case <-ctx.Done():
			return ps.getResults(), nil
		case <-timeout:
			return ps.getResults(), nil
		case packet := <-packetSource.Packets():
			if packet != nil {
				ps.processPacket(packet)
			}
		}
	}
}

func (ps *PassiveScanner) processPacket(packet gopacket.Packet) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	var srcIP, dstIP string
	var srcMAC string
	var ttl uint8
	var isWireless bool
	var detectedProtos []string

	// Decode L2 (Ethernet or 802.11)
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		srcMAC = dot11.Address2.String() // Address2 is typically the transmitter/source
		isWireless = true
		detectedProtos = append(detectedProtos, "802.11")
		
		if ps.wpaDecrypter != nil {
			if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				eapol, _ := eapolLayer.(*layers.EAPOL)
				ps.wpaDecrypter.ProcessEAPOL(dot11, eapol)
			} else if dataLayer := packet.Layer(layers.LayerTypeDot11Data); dataLayer != nil && dot11.Flags.WEP() {
				decrypted, err := ps.wpaDecrypter.DecryptPacket(dot11, dataLayer.LayerPayload())
				if err == nil && len(decrypted) > 0 {
					version := decrypted[0] >> 4
					if version == 4 {
						newPacket := gopacket.NewPacket(decrypted, layers.LayerTypeIPv4, gopacket.Default)
						if newPacket.Layer(layers.LayerTypeIPv4) != nil {
							packet = newPacket
						}
					} else if version == 6 {
						newPacket := gopacket.NewPacket(decrypted, layers.LayerTypeIPv6, gopacket.Default)
						if newPacket.Layer(layers.LayerTypeIPv6) != nil {
							packet = newPacket
						}
					}
				}
			}
		}
	} else if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}

	// 802.1x (EAPOL) Authentication Frames
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		detectedProtos = append(detectedProtos, "802.1X (EAPOL)")
	}

	// CDP / LLDP parsing
	// CDP/LLDP parsing not supported in current gopacket version; placeholder for future implementation
// if cdpLayer := packet.Layer(layers.LayerTypeCDP); cdpLayer != nil {
// 	// ... CDP handling ...
// } else if lldpLayer := packet.Layer(layers.LayerTypeLLDP); lldpLayer != nil {
// 	// ... LLDP handling ...
// }

	// Decode L3
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ttl = ip.TTL
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		ttl = ip.HopLimit
	} else {
		// If it's pure L2 (like an EAPOL frame without an IP yet), we might track it by MAC
		if srcMAC != "" && srcIP == "" {
			srcIP = "MAC:" + srcMAC
		} else {
			return
		}
	}

	host := ps.getOrCreateHost(srcIP)
	if srcMAC != "" && host.MAC == "" {
		host.MAC = srcMAC
	}
	if isWireless {
		ps.addProtocol(host, "Wireless (802.11)")
	}
	for _, proto := range detectedProtos {
		ps.addProtocol(host, proto)
	}

	// Decode L4 (TCP/UDP) & Passive OS Fingerprinting on SYN packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		
		// If it's a SYN packet, analyze it for OS fingerprinting
		if tcp.SYN && !tcp.ACK && host.InferredOS == "" {
			host.InferredOS = fingerprintOS(ttl, tcp.Window, tcp.Options)
		}

		// L7 Decoding (HTTP/TLS)
		if app := packet.ApplicationLayer(); app != nil {
			payload := string(app.Payload())
			if strings.HasPrefix(payload, "GET ") || strings.HasPrefix(payload, "POST ") {
				ps.addProtocol(host, "HTTP")
				// Try to extract Host header
				lines := strings.Split(payload, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "Host: ") {
						hname := strings.TrimSpace(strings.TrimPrefix(line, "Host: "))
						ps.addHostname(host, hname)
					}
				}
			} else if tcp.DstPort == 443 || tcp.SrcPort == 443 {
				// We don't have a full TLS parser here, but we can tag it as TLS
				ps.addProtocol(host, "TLS")
			}
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort == 53 || udp.SrcPort == 53 {
			ps.addProtocol(host, "DNS")
			// Hooking DNS Layer
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				for _, q := range dns.Questions {
					ps.addHostname(host, string(q.Name))
				}
			}
		}
	// Placeholder for future routing protocol parsing (RIP, BGP, OSPF) – not supported by current gopacket version
// TODO: implement custom parsing if needed

		ps.addProtocol(host, "ICMP")
		if app := packet.ApplicationLayer(); app != nil {
			payload := string(app.Payload())
			if len(payload) > 64 {
				entropy := CalculateShannonEntropy(payload)
				if entropy > 4.8 {
					log.Printf("[ANOMALY] High Entropy ICMP Payload (Steganography/Exfil) from %s: %.2f", srcIP, entropy)
					ps.addProtocol(host, fmt.Sprintf("ICMP Tunneling / C2 (Entropy: %.2f)", entropy))
				}
			}
		}
	}

	if errLayer := packet.ErrorLayer(); errLayer != nil {
		if ps.starlarkEngine != nil {
			go ps.starlarkEngine.EvalMalformed(srcIP, srcMAC, fmt.Sprintf("%v", errLayer.Error()))
		}
	}

	_ = dstIP // could track flows, but focusing on host discovery
}

// addNeighbor adds a discovered neighbor, deduplicating by chassis+port+protocol.
// Duplicate GetNeighbors method removed; use implementation from neighbor.go

// Helper methods for routing protocol data
func (ps *PassiveScanner) addRIPInfo(info RIPInfo) {
    for _, existing := range ps.ripInfos {
        if existing.Source == info.Source && existing.Destination == info.Destination {
            return
        }
    }
    ps.ripInfos = append(ps.ripInfos, info)
}

func (ps *PassiveScanner) addBGPInfo(info BGPInfo) {
    for _, existing := range ps.bgpPeers {
        if existing.Asn == info.Asn && existing.NeighborIp == info.NeighborIp {
            return
        }
    }
    ps.bgpPeers = append(ps.bgpPeers, info)
}

func (ps *PassiveScanner) addOSPFInfo(info OSPFInfo) {
    for _, existing := range ps.ospfNeighbors {
        if existing.RouterId == info.RouterId && existing.AreaId == info.AreaId {
            return
        }
    }
    ps.ospfNeighbors = append(ps.ospfNeighbors, info)
}

func (ps *PassiveScanner) addNeighbor(ni NeighborInfo) {
	for _, existing := range ps.neighbors {
		if existing.ChassisID == ni.ChassisID && existing.PortID == ni.PortID && existing.Protocol == ni.Protocol {
			return
		}
	}
	ps.neighbors = append(ps.neighbors, ni)
}

func fingerprintOS(ttl uint8, windowSize uint16, options []layers.TCPOption) string {
	// Passive OS fingerprinting heuristics
	// TTLs are typically initial values of 64 (Linux/Mac) or 128 (Windows) or 255 (Cisco/Network eq)
	// We round up to nearest typical boundary due to hops
	initialTTL := guessInitialTTL(ttl)
	
	if initialTTL == 128 {
		if windowSize == 8192 || windowSize == 64240 {
			return "Windows"
		}
		return "Windows (Generic)"
	} else if initialTTL == 64 {
		if windowSize == 65535 {
			return "macOS / iOS / FreeBSD"
		} else if windowSize == 5840 || windowSize == 29200 || windowSize == 64240 {
			return "Linux"
		}
		return "Linux/Unix"
	}
	
	return fmt.Sprintf("Unknown (TTL:%d, Win:%d)", ttl, windowSize)
}

func guessInitialTTL(ttl uint8) uint8 {
	if ttl <= 64 {
		return 64
	} else if ttl <= 128 {
		return 128
	}
	return 255
}

func (ps *PassiveScanner) getOrCreateHost(ip string) *PassiveHost {
	if h, ok := ps.hosts[ip]; ok {
		return h
	}
	h := &PassiveHost{IP: ip}
	ps.hosts[ip] = h
	return h
}

func (ps *PassiveScanner) addProtocol(h *PassiveHost, proto string) {
	added := false
	for _, p := range h.L7Protocols {
		if p == proto {
			return
		}
	}
	h.L7Protocols = append(h.L7Protocols, proto)
	added = true

	// If we have a programmable script loaded, let it evaluate the host asynchronously
	if added && ps.starlarkEngine != nil {
		go ps.starlarkEngine.EvalPassiveHost(*h)
	}
}

func (ps *PassiveScanner) addHostname(h *PassiveHost, hostname string) {
	if hostname == "" {
		return
	}
	for _, n := range h.Hostnames {
		if n == hostname {
			return
		}
	}
	h.Hostnames = append(h.Hostnames, hostname)

	// Anomaly Detection: DGA Check
	if isDGA, entropy := IsDGA(hostname); isDGA {
		// Log alerting metadata
		log.Printf("[ANOMALY] High Entropy DGA Detected: %s (Entropy: %.2f) from %s", hostname, entropy, h.IP)
		
		// Map as a suspicious protocol/behavior
		ps.addProtocol(h, fmt.Sprintf("Malware C2 (DGA: %.2f)", entropy))
	}
}

func (ps *PassiveScanner) getResults() []PassiveHost {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	res := make([]PassiveHost, 0, len(ps.hosts))
	for _, h := range ps.hosts {
		res = append(res, *h)
	}
	return res
}
