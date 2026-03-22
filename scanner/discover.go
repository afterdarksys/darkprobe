package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Host represents a discovered network host
type Host struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	OpenPorts []int  `json:"open_ports,omitempty"`
}

// DiscoverNetwork scans the local subnet for active hosts and open ports
func DiscoverNetwork(ctx context.Context, subnet string) ([]Host, error) {
	// Parse the subnet
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network and broadcast address for simplicity (IPv4 assumed)
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	hostsCh := make(chan Host, len(ips))
	var wg sync.WaitGroup

	// Common ports to check for OS discovery
	portsToCheck := []int{22, 80, 135, 139, 443, 445, 3389}

	// Rate limiter/worker pool size
	sem := make(chan struct{}, 100)

	for _, targetIP := range ips {
		wg.Add(1)
		go func(tip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Quick ping attempt via TCP (port 22, 135, 445)
			openPorts := scanPorts(tip, portsToCheck)
			if len(openPorts) > 0 {
				host := Host{
					IP:        tip,
					OpenPorts: openPorts,
					OS:        guessOS(openPorts, tip),
				}
				// Try reverse DNS
				names, _ := net.LookupAddr(tip)
				if len(names) > 0 {
					host.Hostname = names[0]
				}
				hostsCh <- host
			}
		}(targetIP)
	}

	wg.Wait()
	close(hostsCh)

	var results []Host
	for h := range hostsCh {
		results = append(results, h)
	}
	
	// Sort by IP for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].IP < results[j].IP
	})

	return results, nil
}

func scanPorts(ip string, ports []int) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			target := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", target, 800*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func guessOS(openPorts []int, ip string) string {
	hasPort := func(p int) bool {
		for _, port := range openPorts {
			if port == p {
				return true
			}
		}
		return false
	}

	if hasPort(445) || hasPort(135) || hasPort(3389) {
		return "Windows"
	}
	if hasPort(22) {
		// Read banner for granular detection
		banner := grabBanner(ip, 22)
		if banner != "" {
			if strings.Contains(banner, "Ubuntu") {
				return "Ubuntu Linux"
			}
			if strings.Contains(banner, "Debian") {
				return "Debian Linux"
			}
		}
		return "Linux/Unix"
	}
	
	// Default
	return "Unknown"
}

func grabBanner(ip string, port int) string {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// Set a deadline for reading
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
