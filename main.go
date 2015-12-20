package main

import (
	"flag"
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 65535
	promiscuous  bool  = true
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
)

var (
	device     = flag.String("i", "any", "interface")
	dst        = flag.String("dst", "", "dst address")
	originPort = flag.Int("org", 80, "original port")
)

func main() {
	flag.Parse()
	// Open device
	println(*device)
	np, err := NewNin2Proxy(*originPort, *dst)
	if err != nil {
		log.Fatal(err)
	}
	np.WaitResponse = 5 * time.Second
	defer np.Close()
	log.Print("start daemon")
	np.Start()
}
