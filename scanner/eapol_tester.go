package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TestEAPOLStart injects an 802.1X EAPOL-Start packet to trigger switch authentication
func TestEAPOLStart(ctx context.Context, iface string) error {
	log.Printf("Initializing EAPOL tester on %s...", iface)

	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %v", err)
	}
	defer handle.Close()

	// Get local MAC
	ifaceInfo, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("could not get interface info: %v", err)
	}
	srcMAC := ifaceInfo.HardwareAddr

	// EAPOL PAE group address
	dstMAC, _ := net.ParseMAC("01:80:c2:00:00:03")

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeEAPOL,
	}

	// Construct EAPOL-Start
	// Version 1, Type 1 (Start), Length 0
	eapolData := []byte{0x01, 0x01, 0x00, 0x00}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true}
	
	if err := gopacket.SerializeLayers(buffer, options, eth, gopacket.Payload(eapolData)); err != nil {
		return fmt.Errorf("failed to serialize EAPOL: %v", err)
	}

	packetBytes := buffer.Bytes()
	log.Printf("Injecting EAPOL-Start frame from %s to PAE Multi-cast %s...", srcMAC.String(), dstMAC.String())
	
	for i := 0; i < 3; i++ {
		if err := handle.WritePacketData(packetBytes); err != nil {
			return fmt.Errorf("failed to inject packet: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	log.Printf("[+] Successfully injected 3 EAPOL-Start frames. Monitor switch ports for state changes!")
	return nil
}
