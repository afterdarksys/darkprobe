package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PassiveHost tracks passively discovered information about a host.
type PassiveHost struct {
	IP          string   `json:"ip"`
	MAC         string   `json:"mac,omitempty"`
	InferredOS  string   `json:"os,omitempty"`
	L7Protocols []string `json:"l7_protocols,omitempty"`
	Hostnames   []string `json:"hostnames,omitempty"`
}

// PassiveScanner accumulates host intelligence from captured packets.
type PassiveScanner struct {
	hosts         map[string]*PassiveHost
	neighbors     []NeighborInfo
	ripInfos      []RIPInfo
	bgpPeers      []BGPInfo
	ospfNeighbors []OSPFInfo
	mu            sync.Mutex
	starlarkEngine *StarlarkEngine
	starlarkSem   chan struct{} // bounds concurrent Starlark goroutines
	wpaDecrypter  *WPADecrypter
}

// NewPassiveScanner returns an initialised PassiveScanner.
func NewPassiveScanner(engine *StarlarkEngine) *PassiveScanner {
	return &PassiveScanner{
		hosts:          make(map[string]*PassiveHost),
		neighbors:      []NeighborInfo{},
		ripInfos:       []RIPInfo{},
		bgpPeers:       []BGPInfo{},
		ospfNeighbors:  []OSPFInfo{},
		starlarkEngine: engine,
		starlarkSem:    make(chan struct{}, 16),
	}
}

// EnableWPA2Decryption arms the scanner to decrypt WPA2-PSK traffic.
func (ps *PassiveScanner) EnableWPA2Decryption(ssid, passphrase string) error {
	ps.wpaDecrypter = NewWPADecrypter(ssid, passphrase)
	return nil
}

// SniffNetwork listens on iface for duration and returns discovered hosts.
func (ps *PassiveScanner) SniffNetwork(ctx context.Context, iface string, duration time.Duration, monitorMode bool) ([]PassiveHost, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("could not create inactive handle: %v", err)
	}
	defer inactive.CleanUp()

	if monitorMode {
		if err = inactive.SetRFMon(true); err != nil {
			log.Printf("Warning: failed to set monitor mode: %v", err)
		}
	}
	if err = inactive.SetSnapLen(1600); err != nil {
		return nil, err
	}
	if err = inactive.SetPromisc(true); err != nil {
		return nil, err
	}
	if err = inactive.SetTimeout(pcap.BlockForever); err != nil {
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

	// ── L2: Ethernet or 802.11 ──────────────────────────────────────────────
	if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		srcMAC = dot11.Address2.String()
		isWireless = true
		detectedProtos = append(detectedProtos, "802.11")

		if ps.wpaDecrypter != nil {
			if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
				eapol, _ := eapolLayer.(*layers.EAPOL)
				ps.wpaDecrypter.ProcessEAPOL(dot11, eapol)
			} else if dataLayer := packet.Layer(layers.LayerTypeDot11Data); dataLayer != nil && dot11.Flags.WEP() {
				decrypted, err := ps.wpaDecrypter.DecryptPacket(dot11, dataLayer.LayerPayload())
				if err == nil && len(decrypted) > 0 {
					switch decrypted[0] >> 4 {
					case 4:
						if np := gopacket.NewPacket(decrypted, layers.LayerTypeIPv4, gopacket.Default); np.Layer(layers.LayerTypeIPv4) != nil {
							packet = np
						}
					case 6:
						if np := gopacket.NewPacket(decrypted, layers.LayerTypeIPv6, gopacket.Default); np.Layer(layers.LayerTypeIPv6) != nil {
							packet = np
						}
					}
				}
			}
		}
	} else if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}

	// 802.1X EAPOL frames
	if packet.Layer(layers.LayerTypeEAPOL) != nil {
		detectedProtos = append(detectedProtos, "802.1X (EAPOL)")
	}

	// ── L3 ───────────────────────────────────────────────────────────────────
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
		// Pure L2 frame (e.g. bare EAPOL) — track by MAC if available.
		if srcMAC != "" {
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

	// ── L4: TCP ──────────────────────────────────────────────────────────────
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// Passive OS fingerprinting from TCP SYN.
		if tcp.SYN && !tcp.ACK && host.InferredOS == "" {
			host.InferredOS = fingerprintOS(ttl, tcp.Window, tcp.Options)
		}

		if app := packet.ApplicationLayer(); app != nil {
			payload := app.Payload()
			payloadStr := string(payload)
			if strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ") ||
				strings.HasPrefix(payloadStr, "PUT ") || strings.HasPrefix(payloadStr, "HTTP/") {
				ps.addProtocol(host, "HTTP")
				for _, line := range strings.Split(payloadStr, "\r\n") {
					if strings.HasPrefix(line, "Host: ") {
						ps.addHostname(host, strings.TrimSpace(strings.TrimPrefix(line, "Host: ")))
					}
				}
			} else if tcp.DstPort == 443 || tcp.SrcPort == 443 {
				ps.addProtocol(host, "TLS")
				// Extract SNI from TLS ClientHello so we capture the target hostname.
				if sni := extractTLSSNI(payload); sni != "" {
					ps.addHostname(host, sni)
				}
			}
		} else if tcp.DstPort == 443 || tcp.SrcPort == 443 {
			ps.addProtocol(host, "TLS")
		}

	// ── L4: UDP ──────────────────────────────────────────────────────────────
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		ps.addProtocol(host, "UDP")
		if udp.DstPort == 53 || udp.SrcPort == 53 {
			ps.addProtocol(host, "DNS")
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				for _, q := range dns.Questions {
					ps.addHostname(host, string(q.Name))
				}
			}
		}

	// ── L4: ICMP ─────────────────────────────────────────────────────────────
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		ps.addProtocol(host, "ICMP")
		if app := packet.ApplicationLayer(); app != nil {
			icmpPayload := string(app.Payload())
			if len(icmpPayload) > 64 {
				entropy := CalculateShannonEntropy(icmpPayload)
				if entropy > 4.8 {
					log.Printf("[ANOMALY] High-entropy ICMP payload from %s (entropy=%.2f) — possible tunnelling/exfil", srcIP, entropy)
					ps.addProtocol(host, fmt.Sprintf("ICMP Tunneling/C2 (entropy=%.2f)", entropy))
				}
			}
		}
	}

	// Pass malformed packets to Starlark plugins (bounded goroutines).
	if errLayer := packet.ErrorLayer(); errLayer != nil && ps.starlarkEngine != nil {
		errMsg := fmt.Sprintf("%v", errLayer.Error())
		select {
		case ps.starlarkSem <- struct{}{}:
			go func() {
				defer func() { <-ps.starlarkSem }()
				ps.starlarkEngine.EvalMalformed(srcIP, srcMAC, errMsg)
			}()
		default:
		}
	}

	_ = dstIP
}

// extractTLSSNI parses a TLS ClientHello and returns the SNI value, or "" if
// the record is not a ClientHello or does not contain an SNI extension.
func extractTLSSNI(payload []byte) string {
	// TLS record layer: ContentType(1) + Version(2) + Length(2)
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	// Handshake layer: HandshakeType(1) + Length(3), starts at byte 5.
	if len(payload) < 9 || payload[5] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	offset := 9 // start of ClientHello body
	// ProtocolVersion(2) + Random(32)
	offset += 2 + 32
	if len(payload) <= offset {
		return ""
	}
	// SessionID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if len(payload) < offset+2 {
		return ""
	}
	// CipherSuites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen
	if len(payload) < offset+1 {
		return ""
	}
	// CompressionMethods
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	// Extensions
	if len(payload) < offset+2 {
		return ""
	}
	extTotalLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	end := offset + extTotalLen
	for offset+4 <= end && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset:])
		extDataLen := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4
		if offset+extDataLen > len(payload) {
			break
		}
		if extType == 0x0000 && extDataLen >= 5 { // SNI extension
			// ServerNameList: length(2) + NameType(1) + NameLength(2) + Name
			nameLen := int(binary.BigEndian.Uint16(payload[offset+3:]))
			if offset+5+nameLen <= len(payload) {
				return string(payload[offset+5 : offset+5+nameLen])
			}
		}
		offset += extDataLen
	}
	return ""
}

// ── Helper methods ────────────────────────────────────────────────────────────

func (ps *PassiveScanner) addNeighbor(ni NeighborInfo) {
	for _, existing := range ps.neighbors {
		if existing.ChassisID == ni.ChassisID && existing.PortID == ni.PortID && existing.Protocol == ni.Protocol {
			return
		}
	}
	ps.neighbors = append(ps.neighbors, ni)
}

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

func fingerprintOS(ttl uint8, windowSize uint16, options []layers.TCPOption) string {
	switch guessInitialTTL(ttl) {
	case 128:
		if windowSize == 8192 || windowSize == 64240 {
			return "Windows"
		}
		return "Windows (Generic)"
	case 64:
		if windowSize == 65535 {
			return "macOS / iOS / FreeBSD"
		}
		if windowSize == 5840 || windowSize == 29200 || windowSize == 64240 {
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

// addProtocol appends proto to the host's protocol list (deduplicating), then
// fires any loaded Starlark plugins asynchronously with a bounded semaphore.
func (ps *PassiveScanner) addProtocol(h *PassiveHost, proto string) {
	for _, p := range h.L7Protocols {
		if p == proto {
			return
		}
	}
	h.L7Protocols = append(h.L7Protocols, proto)

	if ps.starlarkEngine != nil {
		snapshot := *h // copy before goroutine
		select {
		case ps.starlarkSem <- struct{}{}:
			go func() {
				defer func() { <-ps.starlarkSem }()
				ps.starlarkEngine.EvalPassiveHost(snapshot)
			}()
		default:
			// semaphore full; skip this evaluation rather than unbounded growth
		}
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

	if isDGA, entropy := IsDGA(hostname); isDGA {
		log.Printf("[ANOMALY] DGA domain detected: %s (entropy=%.2f) from %s", hostname, entropy, h.IP)
		ps.addProtocol(h, fmt.Sprintf("Malware C2 (DGA entropy=%.2f)", entropy))
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
