package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	pb "github.com/straticus1/ads-darkapi-io/darkprobe/proto"
	"github.com/straticus1/ads-darkapi-io/darkprobe/reporter"
	"github.com/straticus1/ads-darkapi-io/darkprobe/scanner"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// ── Global flags ──────────────────────────────────────────────────────────────

var (
	// Reporting
	endpointFlag string
	apiKeyFlag   string
	jsonOutput   bool
	outputFile   string

	// Remote daemon
	daemonAddr  string
	tlsCertFile string
	jwtFile     string

	// Sniff
	interfaceFlag string
	durationFlag  string
	monitorFlag   bool
	wpaSSIDFlag   string
	wpaPSKFlag    string
	pluginDirFlag string

	// Discover
	subnetFlag      string
	concurrencyFlag int
	portsFlag       string

	// cert
	tlsPort int

	// radius
	radiusServer string
	radiusSecret string
	radiusUser   string
	radiusPass   string

	// jitter
	jitterPort     int
	jitterCount    int
	jitterInterval int

	// sip
	sipPort int
	sipUDP  bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "darkprobe",
	Short: "DarkProbe — network reconnaissance and security testing",
	Run:   func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

// ── Remote client ─────────────────────────────────────────────────────────────

// getRemoteClient dials the daemon with mTLS + JWT. Caller must defer conn.Close().
func getRemoteClient() (*grpc.ClientConn, pb.DarkProbeServiceClient, context.Context, error) {
	caData, err := os.ReadFile(tlsCertFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA cert: %v", err)
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(caData) {
		return nil, nil, nil, fmt.Errorf("failed to append CA certs")
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: cp})
	conn, err := grpc.NewClient(daemonAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}

	tokenBytes, err := os.ReadFile(jwtFile)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("failed to read JWT file: %v", err)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenBytes, &payload); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("invalid JWT JSON: %v", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+payload.Token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	return conn, pb.NewDarkProbeServiceClient(conn), ctx, nil
}

// ── discover ──────────────────────────────────────────────────────────────────

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Actively discover hosts on a subnet via TCP port scanning",
	Run: func(cmd *cobra.Command, args []string) {
		if daemonAddr != "" {
			conn, client, ctx, err := getRemoteClient()
			if err != nil {
				log.Fatalf("Remote client error: %v", err)
			}
			defer conn.Close()
			resp, err := client.Discover(ctx, &pb.DiscoverRequest{Subnet: subnetFlag})
			if err != nil {
				log.Fatalf("Discover RPC error: %v", err)
			}
			for _, h := range resp.Hosts {
				log.Printf(" - %s (MAC: %s, OS: %s)", h.Ip, h.Mac, h.Os)
			}
			return
		}

		ctx := context.Background()
		subnet := subnetFlag
		if subnet == "" {
			subnet = guessDefaultSubnet()
			if subnet == "" {
				log.Fatalf("Could not auto-detect subnet. Use --subnet.")
			}
			log.Printf("Auto-detected subnet: %s", subnet)
		}

		opts := &scanner.DiscoverOptions{
			Concurrency: concurrencyFlag,
			Ports:       parsePorts(portsFlag),
		}
		hosts, err := scanner.DiscoverNetwork(ctx, subnet, opts)
		if err != nil {
			log.Fatalf("Discovery failed: %v", err)
		}
		log.Printf("Discovered %d active host(s).", len(hosts))
		for _, h := range hosts {
			log.Printf(" - %s  OS:%s  Ports:%v  Hostname:%s", h.IP, h.OS, h.OpenPorts, h.Hostname)
		}

		writeOutput(hosts)
		reportActive(ctx, subnet, hosts)
	},
}

// ── sniff ─────────────────────────────────────────────────────────────────────

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Passively sniff traffic for OS fingerprinting and host discovery",
	Run: func(cmd *cobra.Command, args []string) {
		if daemonAddr != "" {
			conn, client, ctx, err := getRemoteClient()
			if err != nil {
				log.Fatalf("Remote client error: %v", err)
			}
			defer conn.Close()
			stream, err := client.Sniff(ctx, &pb.SniffRequest{
				Interface:   interfaceFlag,
				Duration:    durationFlag,
				MonitorMode: monitorFlag,
				WpaSsid:     wpaSSIDFlag,
				WpaPsk:      wpaPSKFlag,
			})
			if err != nil {
				log.Fatalf("Sniff RPC error: %v", err)
			}
			for {
				resp, err := stream.Recv()
				if err != nil {
					break
				}
				log.Printf(" - %s  MAC:%s  OS:%s  L7:%v  Hostnames:%v",
					resp.Ip, resp.Mac, resp.Os, resp.L7Protocols, resp.Hostnames)
			}
			return
		}

		ctx := context.Background()
		if interfaceFlag == "" {
			log.Fatalf("--interface is required")
		}

		var engine *scanner.StarlarkEngine
		if pluginDirFlag != "" {
			var lerr error
			engine, lerr = scanner.LoadPlugins(pluginDirFlag)
			if lerr != nil {
				log.Fatalf("Failed to load Starlark plugins: %v", lerr)
			}
		}

		ps := scanner.NewPassiveScanner(engine)
		if wpaSSIDFlag != "" && wpaPSKFlag != "" {
			if err := ps.EnableWPA2Decryption(wpaSSIDFlag, wpaPSKFlag); err != nil {
				log.Fatalf("WPA2 decryption setup failed: %v", err)
			}
		}

		dur, err := time.ParseDuration(durationFlag)
		if err != nil {
			log.Fatalf("Invalid duration %q: %v", durationFlag, err)
		}

		hosts, err := ps.SniffNetwork(ctx, interfaceFlag, dur, monitorFlag)
		if err != nil {
			log.Fatalf("Sniff failed (need root/CAP_NET_RAW?): %v", err)
		}
		log.Printf("Passive scan complete — %d host(s) observed.", len(hosts))
		for _, h := range hosts {
			log.Printf(" - %s  MAC:%s  OS:%s  Protocols:%v  Hostnames:%v",
				h.IP, h.MAC, h.InferredOS, h.L7Protocols, h.Hostnames)
		}

		writeOutput(hosts)
		if endpointFlag != "" {
			token := resolveToken()
			if token != "" {
				client := reporter.NewClient(endpointFlag, token)
				if err := client.ReportPassive(ctx, "iface:"+interfaceFlag, hosts); err != nil {
					log.Fatalf("Reporting failed: %v", err)
				}
				log.Printf("Telemetry reported to DarkAPI.")
			}
		}
	},
}

// ── cert ──────────────────────────────────────────────────────────────────────

var tlsCmd = &cobra.Command{
	Use:   "cert [domain]",
	Short: "Deep TLS/SSL certificate chain inspection",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if daemonAddr != "" {
			conn, client, ctx, err := getRemoteClient()
			if err != nil {
				log.Fatalf("Remote client error: %v", err)
			}
			defer conn.Close()
			resp, err := client.TLSInspect(ctx, &pb.TLSInspectRequest{Domain: args[0], Port: int32(tlsPort)})
			if err != nil {
				log.Fatalf("TLSInspect RPC error: %v", err)
			}
			log.Printf("TLS inspection result:\n%s", resp.Result)
			return
		}
		if err := scanner.DebugTLS(args[0], tlsPort); err != nil {
			log.Fatalf("TLS inspection failed: %v", err)
		}
	},
}

// ── radius ────────────────────────────────────────────────────────────────────

var radiusCmd = &cobra.Command{
	Use:   "radius",
	Short: "Test RADIUS authentication via Access-Request (PAP)",
	Run: func(cmd *cobra.Command, args []string) {
		if radiusServer == "" || radiusSecret == "" || radiusUser == "" || radiusPass == "" {
			log.Fatalf("--server, --secret, --user, and --pass are all required")
		}
		if err := scanner.TestRADIUSAuth(context.Background(), radiusServer, radiusSecret, radiusUser, radiusPass); err != nil {
			log.Fatalf("RADIUS test failed: %v", err)
		}
	},
}

// ── eapol ─────────────────────────────────────────────────────────────────────

var eapolCmd = &cobra.Command{
	Use:   "eapol",
	Short: "Inject 802.1X EAPOL-Start frames to test port authentication",
	Run: func(cmd *cobra.Command, args []string) {
		if interfaceFlag == "" {
			log.Fatalf("--interface is required")
		}
		if err := scanner.TestEAPOLStart(context.Background(), interfaceFlag); err != nil {
			log.Fatalf("EAPOL test failed: %v", err)
		}
	},
}

// ── dns-trace ─────────────────────────────────────────────────────────────────

var dnsTraceCmd = &cobra.Command{
	Use:   "dns-trace [domain]",
	Short: "Trace recursive DNS resolution from root nameservers",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := scanner.DNSTrace(args[0]); err != nil {
			log.Fatalf("DNS trace failed: %v", err)
		}
	},
}

// ── jitter ────────────────────────────────────────────────────────────────────

var jitterCmd = &cobra.Command{
	Use:   "jitter [target]",
	Short: "Measure UDP jitter and packet loss to a target",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := scanner.UDPJitter(args[0], jitterPort, jitterCount, jitterInterval); err != nil {
			log.Fatalf("Jitter test failed: %v", err)
		}
	},
}

// ── sip ───────────────────────────────────────────────────────────────────────

var sipCmd = &cobra.Command{
	Use:   "sip [target]",
	Short: "Send SIP OPTIONS to discover PBX/SBC systems",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := scanner.TestSIPOptions(args[0], sipPort, sipUDP); err != nil {
			log.Fatalf("SIP probe failed: %v", err)
		}
	},
}

// ── init ──────────────────────────────────────────────────────────────────────

func init() {
	// Persistent (all commands)
	rootCmd.PersistentFlags().StringVar(&endpointFlag, "endpoint", "https://api.darkapi.io/api/v1/darkprobe/telemetry", "DarkAPI telemetry endpoint")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "DarkAPI key (or set DARKAPI_TOKEN)")
	rootCmd.PersistentFlags().StringVar(&daemonAddr, "daemon-addr", "", "gRPC daemon address (e.g. localhost:50051)")
	rootCmd.PersistentFlags().StringVar(&tlsCertFile, "tls", "", "CA cert for mTLS (PEM)")
	rootCmd.PersistentFlags().StringVar(&jwtFile, "jwt", "", `JWT token file {"token":"..."}`)
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Print results as JSON to stdout")
	rootCmd.PersistentFlags().StringVar(&outputFile, "output", "", "Write JSON results to file")

	// discover
	discoverCmd.Flags().StringVar(&subnetFlag, "subnet", "", "Subnet in CIDR notation (auto-detected if omitted)")
	discoverCmd.Flags().IntVar(&concurrencyFlag, "concurrency", 100, "Concurrent scan workers")
	discoverCmd.Flags().StringVar(&portsFlag, "ports", "", "Ports to scan: comma-separated or ranges (e.g. 22,80,443 or 1-1024)")

	// sniff
	sniffCmd.Flags().StringVar(&interfaceFlag, "interface", "", "Network interface (e.g. en0)")
	sniffCmd.Flags().StringVar(&durationFlag, "duration", "30s", "Capture duration")
	sniffCmd.Flags().BoolVar(&monitorFlag, "monitor-mode", false, "Enable 802.11 monitor mode")
	sniffCmd.Flags().StringVar(&wpaSSIDFlag, "wpa-ssid", "", "SSID for WPA2-PSK decryption")
	sniffCmd.Flags().StringVar(&wpaPSKFlag, "wpa-psk", "", "Passphrase for WPA2-PSK decryption")
	sniffCmd.Flags().StringVar(&pluginDirFlag, "plugin-dir", "", "Directory of Starlark (.star) plugins")

	// cert
	tlsCmd.Flags().IntVar(&tlsPort, "port", 443, "TLS port")

	// radius
	radiusCmd.Flags().StringVar(&radiusServer, "server", "", "RADIUS server (host:port)")
	radiusCmd.Flags().StringVar(&radiusSecret, "secret", "", "Shared secret")
	radiusCmd.Flags().StringVar(&radiusUser, "user", "", "Username")
	radiusCmd.Flags().StringVar(&radiusPass, "pass", "", "Password")

	// eapol
	eapolCmd.Flags().StringVar(&interfaceFlag, "interface", "", "Network interface (e.g. eth0)")

	// jitter
	jitterCmd.Flags().IntVar(&jitterPort, "port", 33434, "Target UDP port")
	jitterCmd.Flags().IntVar(&jitterCount, "count", 100, "Number of probe packets")
	jitterCmd.Flags().IntVar(&jitterInterval, "interval", 10, "Inter-packet interval (ms)")

	// sip
	sipCmd.Flags().IntVar(&sipPort, "port", 5060, "SIP port")
	sipCmd.Flags().BoolVar(&sipUDP, "udp", false, "Use UDP transport")

	rootCmd.AddCommand(discoverCmd, sniffCmd, tlsCmd, radiusCmd, eapolCmd, dnsTraceCmd, jitterCmd, sipCmd)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func guessDefaultSubnet() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			_, network, err := net.ParseCIDR(addr.String())
			if err == nil {
				return network.String()
			}
		}
	}
	return ""
}

func resolveToken() string {
	if apiKeyFlag != "" {
		return apiKeyFlag
	}
	return os.Getenv("DARKAPI_TOKEN")
}

func parsePorts(s string) []int {
	if s == "" {
		return nil
	}
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo > hi || lo < 1 || hi > 65535 {
				log.Printf("Skipping invalid port range: %s", part)
				continue
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				log.Printf("Skipping invalid port: %s", part)
				continue
			}
			ports = append(ports, p)
		}
	}
	return ports
}

func writeOutput(v any) {
	if !jsonOutput && outputFile == "" {
		return
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		return
	}
	if outputFile != "" {
		if err := os.WriteFile(outputFile, b, 0644); err != nil {
			log.Printf("Failed to write %s: %v", outputFile, err)
			return
		}
		log.Printf("Results written to %s", outputFile)
	}
	if jsonOutput {
		fmt.Println(string(b))
	}
}

func reportActive(ctx context.Context, subnet string, hosts []scanner.Host) {
	if endpointFlag == "" {
		return
	}
	token := resolveToken()
	if token == "" {
		return
	}
	client := reporter.NewClient(endpointFlag, token)
	if err := client.Report(ctx, subnet, hosts); err != nil {
		log.Fatalf("Reporting failed: %v", err)
	}
	log.Printf("Telemetry reported to DarkAPI.")
}
