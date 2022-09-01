package client

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/crypt"
	"github.com/tact1m4n3/pocket-vpn/handshake"
	"github.com/tact1m4n3/pocket-vpn/packet"
	"github.com/tact1m4n3/pocket-vpn/routes"
	"github.com/tact1m4n3/pocket-vpn/tun"
	"github.com/tact1m4n3/pocket-vpn/util"
)

type Client struct {
	cfg     *config.Config
	wg      *sync.WaitGroup
	quitCh  chan interface{}
	errorCh chan error
	key     []byte
	conn    net.Conn
	iface   *water.Interface
}

func New(cfg *config.Config) *Client {
	c := &Client{
		cfg:     cfg,
		wg:      &sync.WaitGroup{},
		quitCh:  make(chan interface{}),
		errorCh: make(chan error, 1),
	}

	conn, err := net.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("successfully connected to %v", conn.RemoteAddr())
	c.conn = conn

	hinfo, err := handshake.ClientWithServer(conn, cfg.Passphrase)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("handshake done... got key")
	c.key = hinfo.Key

	iface, err := tun.New(&net.IPNet{IP: hinfo.IP.AsSlice(), Mask: net.CIDRMask(128, 128)}, cfg.TunMTU)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using tun interface %v", iface.Name())
	c.iface = iface

	if err := routes.Init(iface, cfg); err != nil {
		log.Fatal(err)
	}
	log.Print("routes configured")

	c.wg.Add(2)
	go c.handleConnection()
	go c.handleTun()

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

func (c *Client) handleConnection() {
	defer c.wg.Done()

	for {
		data, err := util.ReadFromConn(c.conn)
		if err != nil {
			if err == io.EOF {
				c.errorCh <- errors.New("disconnected from server")
				return
			} else {
				select {
				case <-c.quitCh:
					return
				default:
					c.errorCh <- err
					return
				}
			}
		}

		data, err = crypt.Decrypt(data, c.key)
		if err != nil {
			log.Print(err)
			continue
		}

		pkt := packet.Packet(data)
		if c.cfg.LogTraffic {
			log.Printf("sending %v", pkt)
		}

		if _, err := c.iface.Write(pkt); err != nil {
			select {
			case <-c.quitCh:
				return
			default:
				c.errorCh <- err
				return
			}
		}
	}
}

func (c *Client) handleTun() {
	defer c.wg.Done()

	buf := make([]byte, 2000)
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
			log.Printf("received %v", pkt)
		}

		data, err := crypt.Encrypt(pkt, c.key)
		if err != nil {
			c.errorCh <- err
			return
		}

		if err := util.WriteToConn(c.conn, data); err != nil {
			select {
			case <-c.quitCh:
				return
			default:
				c.errorCh <- err
				return
			}
		}
	}
}
