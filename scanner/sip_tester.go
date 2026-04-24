package scanner

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// TestSIPOptions sends an active SIP OPTIONS request to discover PBX footprints
func TestSIPOptions(target string, port int, udp bool) error {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	log.Printf("Starting SIP OPTIONS Ping against %s (UDP: %v)", addr, udp)

	protoStr := "TCP"
	if udp {
		protoStr = "UDP"
	}

	payload := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n"+
		"Via: SIP/2.0/%s %s:%d;branch=z9hG4bK-darkprobe-1\r\n"+
		"Max-Forwards: 70\r\n"+
		"From: <sip:darkprobe@%s>;tag=12345\r\n"+
		"To: <sip:target@%s>\r\n"+
		"Call-ID: darkprobe-options-%d\r\n"+
		"CSeq: 1 OPTIONS\r\n"+
		"Contact: <sip:darkprobe@%s>\r\n"+
		"Accept: application/sdp\r\n"+
		"Content-Length: 0\r\n\r\n", addr, protoStr, "127.0.0.1", port, target, target, time.Now().UnixNano(), "127.0.0.1")

	var conn net.Conn
	var err error

	if udp {
		conn, err = net.DialTimeout("udp", addr, 3*time.Second)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}

	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("Warning: failed to set deadline: %v", err)
	}

	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	// Read response
	scanner := bufio.NewScanner(conn)
	
	// Print first few lines to look for Server headers
	linesRead := 0
	foundServer := ""
	statusCode := ""

	for scanner.Scan() {
		line := scanner.Text()
		if linesRead == 0 {
			statusCode = line
			log.Printf("[+] SIP Response: %s", statusCode)
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") || strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			foundServer = line
			log.Printf("[+] VoIP Fingerprint: %s", foundServer)
		}
		if strings.HasPrefix(line, "Allow:") {
			log.Printf("[+] Supported Methods: %s", line)
		}
		
		linesRead++
		if line == "" || linesRead > 15 {
			break // End of headers
		}
	}

	if err := scanner.Err(); err != nil {
		if !udp { // UDP read might timeout if no response, which is normal
			return fmt.Errorf("read failed: %v", err)
		}
	}

	if statusCode == "" {
		return fmt.Errorf("no response received (target might drop SIP or require specific source IP)")
	}

	return nil
}
