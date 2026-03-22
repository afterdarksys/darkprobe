package scanner

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

// DebugTLS connects to a remote server and performs a deep inspection of its SSL/TLS certificates.
func DebugTLS(domain string, port int) error {
	addr := fmt.Sprintf("%s:%d", domain, port)
	log.Printf("Starting Deep TLS/SSL Inspection against %s...", addr)

	conf := &tls.Config{
		InsecureSkipVerify: true, // we want to securely inspect even invalid/expired certs
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return fmt.Errorf("TLS Dial failed (target might not support TLS on this port): %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	
	tlsVersion := "Unknown"
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0 (DEPRECATED)"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1 (DEPRECATED)"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}

	log.Printf("[+] Connection Established: %s (CipherSuite: %s)", tlsVersion, tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates provided by server")
	}

	for i, cert := range state.PeerCertificates {
		log.Printf("====================[ Certificate %d Depth ]====================", i)
		log.Printf("  Subject:   %s", cert.Subject.String())
		log.Printf("  Issuer:    %s", cert.Issuer.String())
		
		daysUntil := int(time.Until(cert.NotAfter).Hours() / 24)
		log.Printf("  Expires:   %s (in %d days)", cert.NotAfter.Format(time.RFC1123), daysUntil)
		
		isValid := time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter)
		if isValid {
			log.Printf("  Status:    [VALID] Date is within bounds")
		} else {
			log.Printf("  Status:    [INVALID] Certificate is expired or not yet valid!")
		}
		
		log.Printf("  Algorithm: %s", cert.SignatureAlgorithm.String())
		if len(cert.DNSNames) > 0 {
			log.Printf("  SANs:      %v", cert.DNSNames)
		}
	}

	log.Printf("=======================[ Verification ]=======================")
	if err := state.PeerCertificates[0].VerifyHostname(domain); err != nil {
		log.Printf("[-] Hostname Validation FAIL: %v", err)
	} else {
		log.Printf("[+] Hostname Validation PASS: Subject Alternative Names match '%s'", domain)
	}

	return nil
}
