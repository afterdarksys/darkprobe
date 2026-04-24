package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/straticus1/ads-darkapi-io/darkprobe/scanner"
    pb "github.com/straticus1/ads-darkapi-io/darkprobe/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"
)

// jwtInterceptor validates JWT token from metadata.
func jwtInterceptor(secret string) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, fmt.Errorf("missing metadata")
        }
        vals := md["authorization"]
        if len(vals) == 0 {
            return nil, fmt.Errorf("missing authorization token")
        }
        tokenStr := vals[0]
        if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
            tokenStr = tokenStr[7:]
        }
        token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
            if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return []byte(secret), nil
        })
        if err != nil || !token.Valid {
            return nil, fmt.Errorf("invalid JWT token: %v", err)
        }
        return handler(ctx, req)
    }
}

// server implements DarkProbeService.
type server struct {
    pb.UnimplementedDarkProbeServiceServer
}

func (s *server) Discover(ctx context.Context, req *pb.DiscoverRequest) (*pb.DiscoverResponse, error) {
    hosts, err := scanner.DiscoverNetwork(ctx, req.Subnet, nil)
    if err != nil {
        return nil, err
    }
    resp := &pb.DiscoverResponse{}
    for _, h := range hosts {
        resp.Hosts = append(resp.Hosts, &pb.HostInfo{Ip: h.IP, Mac: h.MAC, Os: h.OS})
    }
    return resp, nil
}

func (s *server) Sniff(req *pb.SniffRequest, stream pb.DarkProbeService_SniffServer) error {
    ps := scanner.NewPassiveScanner(nil)
    if req.WpaSsid != "" && req.WpaPsk != "" {
        if err := ps.EnableWPA2Decryption(req.WpaSsid, req.WpaPsk); err != nil {
            return err
        }
    }
    dur, err := time.ParseDuration(req.Duration)
    if err != nil {
        return err
    }
    hosts, err := ps.SniffNetwork(context.Background(), req.Interface, dur, req.MonitorMode)
    if err != nil {
        return err
    }
    for _, h := range hosts {
        resp := &pb.SniffResponse{Ip: h.IP, Mac: h.MAC, Os: h.InferredOS, L7Protocols: h.L7Protocols, Hostnames: h.Hostnames}
        if err := stream.Send(resp); err != nil {
            return err
        }
    }
    return nil
}

func (s *server) TLSInspect(ctx context.Context, req *pb.TLSInspectRequest) (*pb.TLSInspectResponse, error) {
    if err := scanner.DebugTLS(req.Domain, int(req.Port)); err != nil {
        return nil, fmt.Errorf("TLS inspection failed: %v", err)
    }
    return &pb.TLSInspectResponse{Result: fmt.Sprintf("TLS inspection of %s:%d complete (details in daemon log)", req.Domain, req.Port)}, nil
}

func main() {
    // Flags for daemon mode.
    listenAddr := flag.String("listen", "localhost:50051", "gRPC listen address")
    certFile := flag.String("cert", "", "Server TLS certificate (PEM)")
    keyFile := flag.String("key", "", "Server TLS private key (PEM)")
    caFile := flag.String("ca", "", "CA certificate for client verification (PEM)")
    jwtSecret := flag.String("jwt-secret", "", "Shared secret for JWT validation")
    flag.Parse()

    if *certFile == "" || *keyFile == "" || *caFile == "" || *jwtSecret == "" {
        log.Fatalf("All TLS and JWT parameters must be provided")
    }

    // Load server cert.
    cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
    if err != nil {
        log.Fatalf("failed to load server key pair: %v", err)
    }
    // Load CA pool.
    caData, err := ioutil.ReadFile(*caFile)
    if err != nil {
        log.Fatalf("failed to read CA file: %v", err)
    }
    caPool := x509.NewCertPool()
    if !caPool.AppendCertsFromPEM(caData) {
        log.Fatalf("failed to append CA certs")
    }
    tlsCreds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool})

    opts := []grpc.ServerOption{grpc.Creds(tlsCreds), grpc.UnaryInterceptor(jwtInterceptor(*jwtSecret))}
    grpcServer := grpc.NewServer(opts...)
    pb.RegisterDarkProbeServiceServer(grpcServer, &server{})

    lis, err := net.Listen("tcp", *listenAddr)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    log.Printf("Daemon listening on %s", *listenAddr)

    // Set up signal handling for graceful shutdown
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        s := <-sigs
        log.Printf("Received signal %v. Shutting down gRPC server.", s)
        grpcServer.GracefulStop() // Gracefully stop the gRPC server
    }()

    if err := grpcServer.Serve(lis); err != nil {
        log.Fatalf("gRPC server failed: %v", err)
    }
    log.Println("gRPC server stopped.")
}
