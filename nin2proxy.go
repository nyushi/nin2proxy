package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Nin2Proxy struct {
	conns        map[int]net.Conn
	handle       *pcap.Handle
	originPort   int
	proxyDst     string
	WaitResponse time.Duration
}

func NewNin2Proxy(originPort int, proxyDst string) (*Nin2Proxy, error) {
	handle, err = pcap.OpenLive(*device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	p := Nin2Proxy{
		handle:     handle,
		conns:      map[int]net.Conn{},
		originPort: originPort,
		proxyDst:   proxyDst,
	}
	err = p.handle.SetBPFFilter(fmt.Sprintf("tcp and port %d", originPort))
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (p *Nin2Proxy) Close() error {
	p.handle.Close()
	return nil
}

func (p *Nin2Proxy) Start() {
	packetSource := gopacket.NewPacketSource(p.handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		p.ProcessPacket(packet)
	}

}
func (p *Nin2Proxy) ProcessPacket(pkt gopacket.Packet) {
	l := pkt.Layer(layers.LayerTypeTCP)
	if l == nil {
		log.Println("not a tcp")
		return
	}
	tcp, _ := l.(*layers.TCP)
	if int(tcp.DstPort) != p.originPort {
		return
	}
	if tcp.SYN {
		c, err := net.Dial("tcp", p.proxyDst)
		if err != nil {
			log.Print(err)
			return
		}
		p.conns[int(tcp.SrcPort)] = c
		go func() {
			b := make([]byte, 4096)
			for {
				if _, err := c.Read(b); err != nil {
					break
				}
			}
		}()
		return
	} else if tcp.FIN {
		time.AfterFunc(p.WaitResponse, func() {
			c := p.conns[int(tcp.SrcPort)]
			if c == nil {
				return
			}
			c.Close()
		})
	} else {
		al := pkt.ApplicationLayer()
		if al != nil {
			c := p.conns[int(tcp.SrcPort)]
			if c == nil {
				return
			}
			c.Write(al.Payload())
		}
	}
}
