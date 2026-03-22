package scanner

import (
	"context"
	"fmt"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// TestRADIUSAuth sends a generic Access-Request to a RADIUS server using PAP.
func TestRADIUSAuth(ctx context.Context, server, secret, username, password string) error {
	log.Printf("Sending RADIUS Access-Request to %s for user %s...", server, username)

	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	
	if err := rfc2865.UserName_SetString(packet, username); err != nil {
		return fmt.Errorf("failed to set username: %v", err)
	}

	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		return fmt.Errorf("failed to set password: %v", err)
	}

	// Wait for response
	response, err := radius.Exchange(ctx, packet, server)
	if err != nil {
		return fmt.Errorf("RADIUS exchange failed: %v", err)
	}

	if response.Code == radius.CodeAccessAccept {
		log.Printf("[+] RADIUS Authentication SUCCESS for user '%s'", username)
		return nil
	} else if response.Code == radius.CodeAccessReject {
		log.Printf("[-] RADIUS Authentication REJECTED for user '%s'", username)
		return fmt.Errorf("access rejected")
	}

	log.Printf("[-] Unknown RADIUS response code: %v", response.Code)
	return fmt.Errorf("unknown response code: %v", response.Code)
}
