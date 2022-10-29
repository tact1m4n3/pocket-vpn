package client

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/crypt"
	"github.com/tact1m4n3/pocket-vpn/packet"
	"github.com/tact1m4n3/pocket-vpn/routes"
	"github.com/tact1m4n3/pocket-vpn/tun"
	"github.com/tact1m4n3/pocket-vpn/util"
)

type Client struct {
	cfg *config.Config

	wg      *sync.WaitGroup
	quitCh  chan struct{}
	errorCh chan error

	key  []byte
	myIP string

	iface *water.Interface
	conn  *net.UDPConn

	toIfaceCh chan packet.Packet
	toConnCh  chan packet.Packet
}

func New(cfg *config.Config) *Client {
	c := &Client{
		cfg: cfg,

		wg:      &sync.WaitGroup{},
		quitCh:  make(chan struct{}),
		errorCh: make(chan error, 1),

		toIfaceCh: make(chan packet.Packet, 1),
		toConnCh:  make(chan packet.Packet, 1),
	}

	key, err := crypt.GenerateKey(cfg.Passphrase)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated key based on passphrase")
	c.key = key

	myIP, _, err := util.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using ip %v", myIP)
	c.myIP = myIP

	iface, err := tun.New()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using tun interface %v", iface.Name())
	c.iface = iface

	raddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}
	c.conn = conn
	log.Printf("connected to %v...", conn.RemoteAddr())

	if err := tun.Config(iface, cfg); err != nil {
		log.Fatal(err)
	}

	if err := routes.Init(iface, cfg); err != nil {
		log.Fatal(err)
	}
	log.Print("routes configured")

	c.wg.Add(3)
	go c.handleInterface()
	go c.handleConnection()
	go c.keepAlive()

	return c
}

func (c *Client) Wait() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ch:
		log.Print("keyboard interrupt")
	case err := <-c.errorCh:
		log.Print(err)
	}
}

func (c *Client) Shutdown() {
	close(c.quitCh)

	routes.Shutdown(c.iface, c.cfg)
	c.iface.Close()
	c.conn.Close()

	close(c.toIfaceCh)
	close(c.toConnCh)

	c.wg.Wait()
}

func (c *Client) handleInterface() {
	defer c.wg.Done()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		for {
			select {
			case <-c.quitCh:
				return
			case pkt := <-c.toIfaceCh:
				if c.cfg.LogTraffic {
					log.Printf("sending through interface %v", pkt)
				}

				if _, err := c.iface.Write(pkt); err != nil {
					c.errorCh <- err
					return
				}
			}
		}
	}()

	buf := make([]byte, c.cfg.TunMTU)
	for {
		n, err := c.iface.Read(buf)
		if err != nil {
			select {
			case <-c.quitCh:
				return
			default:
				c.errorCh <- err
				return
			}
		}

		pkt := packet.Packet(buf[:n])
		c.toConnCh <- pkt
	}
}

func (c *Client) handleConnection() {
	defer c.wg.Done()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		for {
			select {
			case <-c.quitCh:
				return
			case pkt := <-c.toConnCh:
				if c.cfg.LogTraffic {
					log.Printf("sending through socket %v", pkt)
				}

				data, err := crypt.Encrypt(pkt, c.key)
				if err != nil {
					c.errorCh <- err
					return
				}

				if _, err := c.conn.Write(data); err != nil {
					c.errorCh <- err
					return
				}
			}
		}
	}()

	buf := make([]byte, 2000)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			select {
			case <-c.quitCh:
				return
			default:
				c.errorCh <- err
				return
			}
		}

		data, err := crypt.Decrypt(buf[:n], c.key)
		if err != nil {
			log.Print(err)
			continue
		}

		pkt := packet.Packet(data)
		c.toIfaceCh <- pkt
	}
}

func (c *Client) keepAlive() {
	defer c.wg.Done()

	for {
		pkt := packet.Ping(c.myIP, "0.0.0.0", 0)
		c.toConnCh <- pkt

		select {
		case <-c.quitCh:
			return
		case <-time.After(5 * time.Second):
		}
	}
}
