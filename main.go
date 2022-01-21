package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// base data
var (
	interface_use_flag = flag.String("interface", "", "")
	url_test           = "https://www.google.com"
	defualt_interface  = "eth0"
	err                error
	snapshot_main      int32         = 1024 // set as type 32
	timeout_shot_cap   time.Duration = 40 * time.Second
	handeler_pcap      *pcap.Handle
)

func check_err_cl(err error) bool {
	if err != nil {
		log.Fatal("COULD NOT CAPTURE ON DEVICE OR NETWORK => CLIENT NET DOWN => ", err)
		return true
	}
	return false
}

func handeler_opener(interface_name string, snapshot int32, promiscuous bool) {
	// first test if the client is online
	content_get, err_cltest := http.Get(url_test)
	check_err_cl(err_cltest)
	if content_get.StatusCode == 200 {
		fmt.Println("USER ONLINE/./././././././././././././")
	}
	handeler_pcap, err = pcap.OpenLive(interface_name, snapshot, promiscuous, timeout_shot_cap)
	//
	// error func

	// close the packet capture handeler
	defer handeler_pcap.Close()
	packetSource := gopacket.NewPacketSource(handeler_pcap, handeler_pcap.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func main() {
	// Open device's
	flag.Parse()
	if *interface_use_flag == "" {
		handeler_opener(defualt_interface, snapshot_main, false)
	} else {
		handeler_opener(*interface_use_flag, snapshot_main, false)
	}
}

func printPacketInfo(AF_PACK gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ether_Layer := AF_PACK.Layer(layers.LayerTypeEthernet)
	if ether_Layer != nil {
		PACK_TYPE_ETHERconst, _ := ether_Layer.(*layers.Ethernet)
		fmt.Println("Ethernet layer detected.")
		fmt.Println("Source MAC: ", PACK_TYPE_ETHERconst.SrcMAC)
		fmt.Println("Destination MAC: ", PACK_TYPE_ETHERconst.DstMAC)
		fmt.Println("Ethernet type: ", PACK_TYPE_ETHERconst.EthernetType)
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := AF_PACK.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := AF_PACK.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range AF_PACK.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := AF_PACK.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
	}

	// Check for errors
	if err := AF_PACK.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
