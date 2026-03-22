package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "time"

    "github.com/spf13/cobra"
    "github.com/straticus1/ads-darkapi-io/darkprobe/reporter"
    "github.com/straticus1/ads-darkapi-io/darkprobe/scanner"
    pb "github.com/straticus1/ads-darkapi-io/darkprobe/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"
)

var (
    // Global flags for all commands
    subnetFlag    string
    endpointFlag  string
    apiKeyFlag    string
    interfaceFlag string
    durationFlag  string
    monitorFlag   bool
    wpaSSIDFlag   string
    wpaPSKFlag    string
    // Remote daemon flags
    daemonAddr    string
    tlsCertFile   string
    jwtFile       string
)

func main() {
    // Define flags
    rootCmd.Flags().StringVar(&subnetFlag, "subnet", "", "Subnet to scan in CIDR notation (e.g. 192.168.1.0/24)")
    rootCmd.Flags().StringVar(&endpointFlag, "endpoint", "https://api.darkapi.io/api/v1/darkprobe/telemetry", "DarkAPI telemetry endpoint")
    rootCmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API Key for DarkAPI (or use DARKAPI_TOKEN env var)")
    // Daemon client flags
    rootCmd.PersistentFlags().StringVar(&daemonAddr, "daemon-addr", "", "gRPC daemon address (e.g. localhost:50051). If set, commands are executed remotely")
    rootCmd.PersistentFlags().StringVar(&tlsCertFile, "tls", "", "Path to CA certificate for mTLS client verification")
    rootCmd.PersistentFlags().StringVar(&jwtFile, "jwt", "", "Path to JSON file containing JWT token string (field \"token\")")

    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}

var rootCmd = &cobra.Command{
    Use:   "darkprobe",
    Short: "DarkProbe network discovery utility",
    Long:  "Discovers clients and operating systems on a network and reports them to darkapi.io",
    Run:   func(cmd *cobra.Command, args []string) { cmd.Help() },
}

// ---------- Helper for remote client ----------
func getRemoteClient() (pb.DarkProbeServiceClient, context.Context, error) {
    // Load CA cert
    caData, err := ioutil.ReadFile(tlsCertFile)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to read CA cert: %v", err)
    }
    cp := x509.NewCertPool()
    if !cp.AppendCertsFromPEM(caData) {
        return nil, nil, fmt.Errorf("failed to append CA certs")
    }
    creds := credentials.NewTLS(&tls.Config{RootCAs: cp, InsecureSkipVerify: false})
    conn, err := grpc.Dial(daemonAddr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, nil, fmt.Errorf("failed to dial daemon: %v", err)
    }
    // Load JWT token
    tokenBytes, err := ioutil.ReadFile(jwtFile)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to read JWT file: %v", err)
    }
    var payload struct{ Token string `json:"token"` }
    if err := json.Unmarshal(tokenBytes, &payload); err != nil {
        return nil, nil, fmt.Errorf("invalid JWT JSON: %v", err)
    }
    md := metadata.Pairs("authorization", "Bearer "+payload.Token)
    ctx := metadata.NewOutgoingContext(context.Background(), md)
    return pb.NewDarkProbeServiceClient(conn), ctx, nil
}

// ---------- discover command ----------
var discoverCmd = &cobra.Command{
    Use:   "discover",
    Short: "Discover network hosts",
    Run: func(cmd *cobra.Command, args []string) {
        if daemonAddr != "" {
            client, ctx, err := getRemoteClient()
            if err != nil { log.Fatalf("Remote client error: %v", err) }
            resp, err := client.Discover(ctx, &pb.DiscoverRequest{Subnet: subnetFlag})
            if err != nil { log.Fatalf("Discover RPC error: %v", err) }
            for _, h := range resp.Hosts {
                log.Printf(" - %s (MAC: %s, OS: %s)", h.Ip, h.Mac, h.Os)
            }
            return
        }
        // Local execution
        ctx := context.Background()
        targetSubnet := subnetFlag
        if targetSubnet == "" {
            targetSubnet = guessDefaultSubnet()
            if targetSubnet == "" {
                log.Fatalf("Could not auto-detect subnet. Please provide --subnet.")
            }
            log.Printf("Auto-detected subnet: %s\n", targetSubnet)
        }
        hosts, err := scanner.DiscoverNetwork(ctx, targetSubnet)
        if err != nil { log.Fatalf("Discovery failed: %v", err) }
        log.Printf("Discovered %d active hosts.\n", len(hosts))
        for _, h := range hosts {
            log.Printf(" - %s (OS: %s, Ports: %v, Hostname: %s)\n", h.IP, h.OS, h.OpenPorts, h.Hostname)
        }
    },
}

// ---------- sniff command ----------
var sniffCmd = &cobra.Command{
    Use:   "sniff",
    Short: "Passively listen to network traffic for OS footprinting and discovery",
    Run: func(cmd *cobra.Command, args []string) {
        if daemonAddr != "" {
            client, ctx, err := getRemoteClient()
            if err != nil { log.Fatalf("Remote client error: %v", err) }
            stream, err := client.Sniff(ctx, &pb.SniffRequest{Interface: interfaceFlag, Duration: durationFlag, MonitorMode: monitorFlag, WpaSsid: wpaSSIDFlag, WpaPsk: wpaPSKFlag})
            if err != nil { log.Fatalf("Sniff RPC error: %v", err) }
            for {
                resp, err := stream.Recv()
                if err != nil { break }
                log.Printf(" - %s (MAC: %s, OS: %s, L7: %v, Hostnames: %v)\n", resp.Ip, resp.Mac, resp.Os, resp.L7Protocols, resp.Hostnames)
            }
            return
        }
        // Local execution (existing logic)
        ctx := context.Background()
        if interfaceFlag == "" { log.Fatalf("Must specify interface (--interface)") }
        var engine *scanner.StarlarkEngine
        if pluginDirFlag != "" {
            var lerr error
            engine, lerr = scanner.LoadPlugins(pluginDirFlag)
            if lerr != nil { log.Fatalf("Failed to load starlark plugins: %v", lerr) }
        }
        ps := scanner.NewPassiveScanner(engine)
        if wpaSSIDFlag != "" && wpaPSKFlag != "" {
            if err := ps.EnableWPA2Decryption(wpaSSIDFlag, wpaPSKFlag); err != nil { log.Fatalf("Failed to enable WPA2 decryption: %v", err) }
        }
        dur, err := time.ParseDuration(durationFlag)
        if err != nil { log.Fatalf("Invalid duration: %v", err) }
        hosts, err := ps.SniffNetwork(ctx, interfaceFlag, dur, monitorFlag)
        if err != nil { log.Fatalf("Sniff failed (do you have root/CAP_NET_RAW?): %v", err) }
        log.Printf("Collected passive telemetry for %d hosts.\n", len(hosts))
        for _, h := range hosts {
            log.Printf(" - %s (MAC: %s, OS: %s, App Layers: %v, Hostnames: %v)\n", h.IP, h.MAC, h.InferredOS, h.L7Protocols, h.Hostnames)
        }
        if endpointFlag != "" && apiKeyFlag != "" {
            client := reporter.NewClient(endpointFlag, apiKeyFlag)
            if err := client.ReportPassive(ctx, "Iface:"+interfaceFlag, hosts); err != nil { log.Fatalf("Reporting failed: %v", err) }
            log.Printf("Successfully reported telemetry to DarkAPI.\n")
        } else {
            log.Println("Skipping telemetry report (missing --endpoint or --api-key).")
        }
    },
}

// ---------- TLS inspect command ----------
var tlsCmd = &cobra.Command{
    Use:   "cert [domain]",
    Short: "Perform deep SSL/TLS certificate chain inspection and validation",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        if daemonAddr != "" {
            client, ctx, err := getRemoteClient()
            if err != nil { log.Fatalf("Remote client error: %v", err) }
            resp, err := client.TLSInspect(ctx, &pb.TLSInspectRequest{Domain: args[0], Port: int32(tlsPort)})
            if err != nil { log.Fatalf("TLSInspect RPC error: %v", err) }
            log.Printf("TLS Inspection result: %s\n", resp.Result)
            return
        }
        // Local execution
        if err := scanner.DebugTLS(args[0], tlsPort); err != nil { log.Fatalf("TLS Inspection failed: %v", err) }
    },
}

// ---------- other commands (radius, eapol, etc.) unchanged ----------
var radiusCmd = &cobra.Command{ /* unchanged placeholder */ }
var eapolCmd = &cobra.Command{ /* unchanged placeholder */ }
var dnsTraceCmd = &cobra.Command{ /* unchanged placeholder */ }
var jitterCmd = &cobra.Command{ /* unchanged placeholder */ }
var sipCmd = &cobra.Command{ /* unchanged placeholder */ }

func init() {
    // Global flags already added above via rootCmd.Flags()
    // Sniff command flags
    sniffCmd.Flags().StringVar(&interfaceFlag, "interface", "", "Network interface to sniff (e.g. en0)")
    sniffCmd.Flags().StringVar(&durationFlag, "duration", "30s", "Duration to passively sniff")
    sniffCmd.Flags().BoolVar(&monitorFlag, "monitor-mode", false, "Enable monitor mode on the interface")
    sniffCmd.Flags().StringVar(&wpaSSIDFlag, "wpa-ssid", "", "SSID of the target WPA2 network for decryption")
    sniffCmd.Flags().StringVar(&wpaPSKFlag, "wpa-psk", "", "Pre-Shared Key (Passphrase) for WPA2 decryption")
    // Add commands to root
    rootCmd.AddCommand(discoverCmd)
    rootCmd.AddCommand(sniffCmd)
    rootCmd.AddCommand(tlsCmd)
    // Other commands (placeholders) could be added similarly if needed
}

func guessDefaultSubnet() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil { return "" }
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                _, network, err := net.ParseCIDR(addr.String())
                if err == nil { return network.String() }
            }
        }
    }
    return ""
}
