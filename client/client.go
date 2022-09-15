package client

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

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

	key []byte
	ip  string

	iface *water.Interface
	conn  *net.UDPConn
}

func New(cfg *config.Config) *Client {
	c := &Client{
		cfg: cfg,

		wg:      &sync.WaitGroup{},
		quitCh:  make(chan struct{}),
		errorCh: make(chan error, 1),
	}

	key, err := crypt.GenerateKey(cfg.Passphrase)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated key based on passphrase")
	c.key = key

	ip, _, err := util.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using ip %v", ip)
	c.ip = ip

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

	c.wg.Add(2)
	go c.handleInterface()
	go c.handleConnection()

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

	c.wg.Wait()
}

func (c *Client) handleInterface() {
	defer c.wg.Done()

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
		if c.cfg.LogTraffic {
			log.Printf("sending %v", pkt)
		}

		data, err := crypt.Encrypt(pkt, c.key)
		if err != nil {
			log.Print(err)
			continue
		}

		if _, err := c.conn.Write(data); err != nil {
			c.errorCh <- err
			return
		}
	}
}

func (c *Client) handleConnection() {
	defer c.wg.Done()

	for i := 0; i < 5; i++ {
		hello := packet.Ping(c.ip, "0.0.0.0", i)
		if c.cfg.LogTraffic {
			log.Printf("sending %v", hello)
		}

		data, err := crypt.Encrypt(hello, c.key)
		if err != nil {
			c.errorCh <- err
			return
		}

		if _, err := c.conn.Write(data); err != nil {
			c.errorCh <- err
			return
		}
	}

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
		if c.cfg.LogTraffic {
			log.Printf("received %v", pkt)
		}

		if _, err := c.iface.Write(pkt); err != nil {
			c.errorCh <- err
			return
		}
	}
}
