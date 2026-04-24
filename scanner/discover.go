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

// Host represents a discovered network host.
type Host struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	OpenPorts []int  `json:"open_ports,omitempty"`
}

// DiscoverOptions controls scan behaviour. Pass nil to use defaults.
type DiscoverOptions struct {
	Concurrency int   // concurrent workers (default 100)
	Ports       []int // ports to probe (default: common set)
}

var defaultPorts = []int{22, 80, 135, 139, 443, 445, 3389}

// DiscoverNetwork scans a subnet for active hosts via TCP port probing.
func DiscoverNetwork(ctx context.Context, subnet string, opts *DiscoverOptions) ([]Host, error) {
	concurrency := 100
	ports := defaultPorts
	if opts != nil {
		if opts.Concurrency > 0 {
			concurrency = opts.Concurrency
		}
		if len(opts.Ports) > 0 {
			ports = opts.Ports
		}
	}

	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	var ips []string
	for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	// Drop network and broadcast addresses (IPv4).
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	hostsCh := make(chan Host, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, targetIP := range ips {
		wg.Add(1)
		go func(tip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			openPorts := scanPorts(tip, ports)
			if len(openPorts) == 0 {
				return
			}
			host := Host{
				IP:        tip,
				OpenPorts: openPorts,
				OS:        guessOS(openPorts, tip),
			}
			if names, _ := net.LookupAddr(tip); len(names) > 0 {
				host.Hostname = names[0]
			}
			hostsCh <- host
		}(targetIP)
	}

	wg.Wait()
	close(hostsCh)

	var results []Host
	for h := range hostsCh {
		results = append(results, h)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].IP < results[j].IP
	})
	return results, nil
}

func scanPorts(ip string, ports []int) []int {
	var (
		open []int
		mu   sync.Mutex
		wg   sync.WaitGroup
	)
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 800*time.Millisecond)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
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
		banner := grabBanner(ip, 22)
		if strings.Contains(banner, "Ubuntu") {
			return "Ubuntu Linux"
		}
		if strings.Contains(banner, "Debian") {
			return "Debian Linux"
		}
		return "Linux/Unix"
	}
	return "Unknown"
}

func grabBanner(ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// cloneIP returns a copy of ip so we can safely increment it without aliasing.
func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
