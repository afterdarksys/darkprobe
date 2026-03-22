package scanner

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/pschlump/aesccm"
	"golang.org/x/crypto/pbkdf2"
)

type WPADecrypter struct {
	ssid       string
	passphrase string
	pmk        []byte
	// Tracks 4-way handshake parameters per client MAC
	ClientStates map[string]*WPAClientState
}

type WPAClientState struct {
	ClientMAC [6]byte
	BSSID     [6]byte
	ANonce    []byte
	SNonce    []byte
	PTK       []byte
	Valid     bool
}

func NewWPADecrypter(ssid, passphrase string) *WPADecrypter {
	pmk := pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, 32, sha1.New)
	return &WPADecrypter{
		ssid:         ssid,
		passphrase:   passphrase,
		pmk:          pmk,
		ClientStates: make(map[string]*WPAClientState),
	}
}

// Custom PRF-512 implementation for WPA2
func prf512(key []byte, label []byte, data []byte) []byte {
	out := make([]byte, 0, 64)
	buf := make([]byte, len(label)+1+len(data)+1)
	copy(buf, label)
	buf[len(label)] = 0
	copy(buf[len(label)+1:], data)
	for i := byte(0); i < 4; i++ {
		buf[len(buf)-1] = i
		mac := hmac.New(sha1.New, key)
		mac.Write(buf)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:64]
}

func (w *WPADecrypter) ProcessEAPOL(dot11 *layers.Dot11, eapol *layers.EAPOL) {
	payload := eapol.Payload
	if len(payload) < 45 {
		return // Not a valid EAPOL Key frame
	}

	keyInfo := binary.BigEndian.Uint16(payload[1:3])
	isPairwise := (keyInfo & 0x0008) != 0 // Bit 3 is Pairwise
	if !isPairwise {
		return
	}
	
	nonce := payload[13:45]
	
	// Determine AP and Client
	isAP := (dot11.Flags & layers.Dot11FlagsFromDS) != 0
	var apMAC, clientMAC [6]byte
	
	if isAP {
		copy(apMAC[:], dot11.Address2) // Transmitter (AP)
		copy(clientMAC[:], dot11.Address1) // Receiver (Client)
	} else {
		copy(clientMAC[:], dot11.Address2) // Transmitter (Client)
		copy(apMAC[:], dot11.Address1) // Receiver (AP)
	}
	
	clientMACStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
	
	state, ok := w.ClientStates[clientMACStr]
	if !ok {
		state = &WPAClientState{
			ClientMAC: clientMAC,
			BSSID:     apMAC,
		}
		w.ClientStates[clientMACStr] = state
	}
	
	keyAck := (keyInfo & 0x0080) != 0 // Key ACK bit
	
	if keyAck {
		// Msg 1 or 3 -> From AP
		state.ANonce = make([]byte, 32)
		copy(state.ANonce, nonce)
	} else {
		// Msg 2 or 4 -> From Client
		state.SNonce = make([]byte, 32)
		copy(state.SNonce, nonce)
	}
	
	if state.ANonce != nil && state.SNonce != nil && !state.Valid {
		// Calculate PTK
		minMac := clientMAC[:]
		maxMac := apMAC[:]
		if string(minMac) > string(maxMac) {
			minMac, maxMac = maxMac, minMac
		}
		minNonce := state.SNonce
		maxNonce := state.ANonce
		if string(minNonce) > string(maxNonce) {
			minNonce, maxNonce = maxNonce, minNonce
		}
		
		data := make([]byte, 0, 76)
		data = append(data, minMac...)
		data = append(data, maxMac...)
		data = append(data, minNonce...)
		data = append(data, maxNonce...)
		
		state.PTK = prf512(w.pmk, []byte("Pairwise key expansion"), data)
		state.Valid = true
		log.Printf("[WPA2] Captured 4-Way Handshake. Derived PTK for %s", clientMACStr)
	}
}

func (w *WPADecrypter) DecryptPacket(dot11 *layers.Dot11, payload []byte) ([]byte, error) {
	if !dot11.Flags.WEP() {
		return payload, nil
	}
	// CCMP header is 8 bytes.
	if len(payload) < 8 {
		return nil, fmt.Errorf("payload too short for CCMP")
	}
	
	pn := make([]byte, 6)
	pn[0] = payload[7] // PN5
	pn[1] = payload[6] // PN4
	pn[2] = payload[5] // PN3
	pn[3] = payload[4] // PN2
	pn[4] = payload[1] // PN1
	pn[5] = payload[0] // PN0
	
	ccmpData := payload[8:]
	
	// Determine client MAC for PTK
	isFromDS := (dot11.Flags & layers.Dot11FlagsFromDS) != 0
	isToDS := (dot11.Flags & layers.Dot11FlagsToDS) != 0
	
	var clientMAC [6]byte
	switch {
	case !isFromDS && !isToDS: // IBSS
		copy(clientMAC[:], dot11.Address2)
	case !isFromDS && isToDS: // To AP
		copy(clientMAC[:], dot11.Address2)
	case isFromDS && !isToDS: // From AP
		copy(clientMAC[:], dot11.Address1)
	case isFromDS && isToDS: // WDS
		return nil, fmt.Errorf("WDS CCMP not supported")
	}
	
	clientMACStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5])
	state, ok := w.ClientStates[clientMACStr]
	if !ok || !state.Valid {
		return nil, fmt.Errorf("missing PTK for %s", clientMACStr)
	}
	
	tk := state.PTK[32:48]
	
	c, err := aes.NewCipher(tk)
	if err != nil {
		return nil, err
	}
	
	nonce := make([]byte, 13)
	nonce[0] = 0 // Priority
	copy(nonce[1:7], dot11.Address2)
	copy(nonce[7:13], pn)
	
	ccm, err := aesccm.NewCCM(c, 8, 13)
	if err != nil {
		return nil, err
	}
	
	aad := make([]byte, 22) // Standard data frame AAD length without QoS
	if dot11.Type.MainType() == layers.Dot11TypeData && dot11.Type.QOS() {
		aad = make([]byte, 24)
	}

	copy(aad[0:2], dot11.Contents[0:2])
	aad[1] &= 0x8F // Mask out Power Management, More Data, WEP
	aad[1] &^= 0x40 // WEP bit = 0
	copy(aad[2:8], dot11.Address1)
	copy(aad[8:14], dot11.Address2)
	copy(aad[14:20], dot11.Address3)
	aad[20] = dot11.Contents[22] & 0x0F // Sequence Control (Fragment number)
	aad[21] = 0
	
	if len(aad) > 22 {
		aad[22] = dot11.Contents[24]
		aad[23] = dot11.Contents[25] & 0x0F
	}
	
	decrypted, err := ccm.Open(nil, nonce, ccmpData, aad)
	if err != nil {
		return nil, err
	}
	
	// Remove LLC/SNAP header (8 bytes)
	if len(decrypted) > 8 {
		decrypted = decrypted[8:]
	}
	
	return decrypted, nil
}
