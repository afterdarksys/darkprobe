package scanner

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSTrace recursively resolves a domain starting from the root servers.
func DNSTrace(domain string) error {
	domain = dns.Fqdn(domain)
	log.Printf("Starting DNS trace for: %s", domain)

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

	targetServer := servers[rand.Intn(len(servers))]
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	msg.RecursionDesired = false

	client := &dns.Client{Timeout: 2 * time.Second}
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
		glue := make(map[string]string)
		for _, ext := range resp.Extra {
			if a, ok := ext.(*dns.A); ok {
				glue[a.Header().Name] = a.A.String()
			}
		}
		var nextServers []string
		for _, ns := range resp.Ns {
			if n, ok := ns.(*dns.NS); ok {
				nsName := n.Ns
				if ip, hasGlue := glue[nsName]; hasGlue {
					log.Printf("%s   %s (glue: %s)", indent, nsName, ip)
					nextServers = append(nextServers, ip)
				} else {
					log.Printf("%s   %s (no glue, resolving...)", indent, nsName)
					if resolvedIP, rErr := resolveA(nsName); rErr == nil {
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
		return "", fmt.Errorf("failed to resolve %s", domain)
	}
	return ips[0], nil
}

// UDPJitter sends count UDP probes to target:port at intervalMs cadence and
// measures round-trip time, packet loss, and jitter from echo responses.
// If the target has no echo service, one-way loss is reported instead.
func UDPJitter(target string, port int, count int, intervalMs int) error {
	if count <= 0 {
		return fmt.Errorf("count must be > 0")
	}
	if intervalMs <= 0 {
		intervalMs = 10
	}

	addr := net.JoinHostPort(target, strconv.Itoa(port))
	log.Printf("UDP jitter test → %s  packets=%d  interval=%dms", addr, count, intervalMs)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %v", addr, err)
	}
	defer conn.Close()

	var rtts []time.Duration
	sent, received := 0, 0
	interval := time.Duration(intervalMs) * time.Millisecond

	for i := 1; i <= count; i++ {
		sendTime := time.Now()
		payload := fmt.Sprintf("DARKPROBE-JITTER SEQ:%d TS:%d", i, sendTime.UnixNano())

		if _, err := conn.Write([]byte(payload)); err != nil {
			log.Printf("[!] Probe %d: send error: %v", i, err)
			time.Sleep(interval)
			continue
		}
		sent++

		// Wait up to one interval for an echo response.
		conn.SetReadDeadline(time.Now().Add(interval))
		buf := make([]byte, 256)
		n, readErr := conn.Read(buf)
		recvTime := time.Now()

		if readErr == nil && n > 0 {
			rtt := recvTime.Sub(sendTime)
			rtts = append(rtts, rtt)
			received++
			log.Printf("Probe %3d: RTT=%.2f ms", i, msec(rtt))
		} else {
			log.Printf("Probe %3d: no response", i)
			// Sleep for remaining interval so cadence stays consistent.
			if elapsed := time.Since(sendTime); elapsed < interval {
				time.Sleep(interval - elapsed)
			}
		}
	}

	// ── Summary ──────────────────────────────────────────────────────────────
	lossRate := 0.0
	if sent > 0 {
		lossRate = float64(sent-received) / float64(sent) * 100.0
	}
	log.Printf("--- Jitter test complete ---")
	log.Printf("Sent: %d  Received: %d  Loss: %.1f%%", sent, received, lossRate)

	switch {
	case len(rtts) >= 2:
		minRTT, maxRTT := rtts[0], rtts[0]
		var sum time.Duration
		for _, r := range rtts {
			sum += r
			if r < minRTT {
				minRTT = r
			}
			if r > maxRTT {
				maxRTT = r
			}
		}
		avgRTT := sum / time.Duration(len(rtts))

		// Jitter = mean absolute deviation between consecutive RTTs (RFC 3550 style).
		var jitterSum float64
		for i := 1; i < len(rtts); i++ {
			jitterSum += math.Abs(float64(rtts[i]-rtts[i-1]) / float64(time.Millisecond))
		}
		avgJitter := jitterSum / float64(len(rtts)-1)

		log.Printf("RTT  min=%.2f ms  max=%.2f ms  avg=%.2f ms  jitter=%.2f ms",
			msec(minRTT), msec(maxRTT), msec(avgRTT), avgJitter)

	case len(rtts) == 1:
		log.Printf("RTT=%.2f ms (single response; cannot calculate jitter)", msec(rtts[0]))

	default:
		log.Printf("No echo responses received.")
		log.Printf("Tip: run `socat UDP-LISTEN:%d,fork PIPE` on the target to enable echo.", port)
	}

	return nil
}

func msec(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
