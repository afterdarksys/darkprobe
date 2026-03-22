package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateMTLSCerts creates a new CA, Server Certificate, and Client Certificate
// for use in darkprobed gRPC communications.
func GenerateMTLSCerts(certDir string) error {
	caKey, caCertBytes, err := generateCA()
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return err
	}

	serverKey, serverCertBytes, err := generateCert(caCert, caKey, "darkapi-gateway", []string{"localhost", "api.darkapi.io"}, false)
	if err != nil {
		return err
	}

	clientKey, clientCertBytes, err := generateCert(caCert, caKey, "darkprobed-agent", nil, true)
	if err != nil {
		return err
	}

	// Write CA
	if err := writePEM(certDir+"/ca.crt", "CERTIFICATE", caCertBytes); err != nil {
		return err
	}

	// Write Server
	if err := writePEM(certDir+"/server.crt", "CERTIFICATE", serverCertBytes); err != nil {
		return err
	}
	serverKeyBytes, _ := x509.MarshalECPrivateKey(serverKey.(*ecdsa.PrivateKey))
	if err := writePEM(certDir+"/server.key", "EC PRIVATE KEY", serverKeyBytes); err != nil {
		return err
	}

	// Write Client
	if err := writePEM(certDir+"/client.crt", "CERTIFICATE", clientCertBytes); err != nil {
		return err
	}
	clientKeyBytes, _ := x509.MarshalECPrivateKey(clientKey.(*ecdsa.PrivateKey))
	if err := writePEM(certDir+"/client.key", "EC PRIVATE KEY", clientKeyBytes); err != nil {
		return err
	}

	return nil
}

func generateCA() (interface{}, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DarkAPI Enterprise Solutions"},
			CommonName:   "DarkAPI Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return key, certBytes, err
}

func generateCert(caCert *x509.Certificate, caKey interface{}, commonName string, dnsNames []string, isClient bool) (interface{}, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"DarkAPI Network Sensors"},
			CommonName:   commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
	}

	if isClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	return key, certBytes, err
}

func writePEM(filename, blockType string, bytes []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", filename, err)
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: bytes})
}
