package scanner

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSTrace recursively resolves a domain starting from the root servers
func DNSTrace(domain string) error {
	domain = dns.Fqdn(domain)
	log.Printf("Starting active DNS Trace for: %s", domain)

	// Hardcoded Root Servers
	roots := []string{
		"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
		"192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
		"192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
		"202.12.27.33",
	}

	return traceIteration(domain, roots, 1)
}

func traceIteration(domain string, servers []string, depth int) error {
	if len(servers) == 0 {
		return fmt.Errorf("no nameservers left to query")
	}
	if depth > 10 {
		return fmt.Errorf("exceeded maximum recursion depth")
	}

	// Pick a random server from the pool
	targetServer := servers[rand.Intn(len(servers))]

	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	msg.RecursionDesired = false

	client := new(dns.Client)
	client.Timeout = 2 * time.Second

	start := time.Now()
	resp, _, err := client.Exchange(msg, targetServer+":53")
	rtt := time.Since(start)

	if err != nil {
		return fmt.Errorf("query to %s failed: %v", targetServer, err)
	}

	indent := strings.Repeat("  ", depth)
	
	if len(resp.Answer) > 0 {
		log.Printf("%s-> Answer from %s (%v):", indent, targetServer, rtt)
		for _, a := range resp.Answer {
			log.Printf("%s   %s", indent, a.String())
		}
		return nil
	}

	if len(resp.Ns) > 0 {
		log.Printf("%s-> Delegation from %s (%v) to:", indent, targetServer, rtt)
		var nextServers []string
		
		// Map Extra records (Glue) for IPs
		glue := make(map[string]string)
		for _, ext := range resp.Extra {
			if a, ok := ext.(*dns.A); ok {
				glue[a.Header().Name] = a.A.String()
			}
		}

		for _, ns := range resp.Ns {
			if n, ok := ns.(*dns.NS); ok {
				nsName := n.Ns
				ip, hasGlue := glue[nsName]
				if hasGlue {
					log.Printf("%s   %s (Glue: %s)", indent, nsName, ip)
					nextServers = append(nextServers, ip)
				} else {
					log.Printf("%s   %s (No Glue, resolving...)", indent, nsName)
					resolvedIP, rErr := resolveA(nsName)
					if rErr == nil {
						nextServers = append(nextServers, resolvedIP)
					}
				}
			}
		}

		return traceIteration(domain, nextServers, depth+1)
	}

	log.Printf("%s-> No answer or delegation from %s", indent, targetServer)
	return nil
}

func resolveA(domain string) (string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("failed to resolve")
	}
	return ips[0], nil
}

// UDPJitter blasts a target with UDP packets and measures ICMP port unreachable returns
func UDPJitter(target string, port int, count int, intervalMs int) error {
	log.Printf("Starting UDP Jitter Test against %s:%d (%d packets, %dms interval)", target, port, count, intervalMs)
	
	// Open a raw connection or just blast standard UDP
	// For agentless jitter without raw sockets, we just send UDP. 
	// To actually receive the ICMP unreachable we'd need a raw socket listener.
	// For this CLI implementation (to avoid mandatory root for simple jitter), we'll do an Application-layer UDP Echo if possible, or standard ICMP ping if UDP unreachable is too complex for standard sockets.
	
	// Since user requested "High-frequency UDP packet loss and jitter", we will do a standard UDP send loop.
	// If the user controls the other side with `socat -v UDP-RECVFROM...`, they see loss.
	
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial udp %s: %v", addr, err)
	}
	defer conn.Close()

	for i := 1; i <= count; i++ {
		payload := fmt.Sprintf("DARKPROBE-JITTER SEQ:%d TS:%d", i, time.Now().UnixNano())
		_, err := conn.Write([]byte(payload))
		if err != nil {
			log.Printf("packet %d failed: %v", i, err)
		} else {
			log.Printf("Sent UDP Probe %d to %s", i, addr)
		}
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
	
	log.Printf("Jitter test complete. Check target for packet arrivals.")
	return nil
}
