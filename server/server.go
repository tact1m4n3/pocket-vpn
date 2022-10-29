package server

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/crypt"
	"github.com/tact1m4n3/pocket-vpn/firewall"
	"github.com/tact1m4n3/pocket-vpn/packet"
	"github.com/tact1m4n3/pocket-vpn/tun"
	"github.com/tact1m4n3/pocket-vpn/util"
)

type Server struct {
	cfg *config.Config

	wg      *sync.WaitGroup
	quitCh  chan struct{}
	errorCh chan error

	key     []byte
	myIP    string
	network string

	clients *cache.Cache

	iface *water.Interface
	conn  *net.UDPConn

	toIfaceCh chan packet.Packet
	toConnCh  chan packet.Packet
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg: cfg,

		wg:      &sync.WaitGroup{},
		quitCh:  make(chan struct{}),
		errorCh: make(chan error, 1),

		clients: cache.New(20*time.Second, 20*time.Second),

		toIfaceCh: make(chan packet.Packet, 1),
		toConnCh:  make(chan packet.Packet, 1),
	}

	key, err := crypt.GenerateKey(cfg.Passphrase)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated key based on passphrase")
	s.key = key

	myIP, network, err := util.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using ip %v in network %v", myIP, network)
	s.myIP = myIP
	s.network = network

	iface, err := tun.New()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using tun interface %v", iface.Name())
	s.iface = iface

	laddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("started server on %v", laddr)
	s.conn = conn

	if err := tun.Config(iface, cfg); err != nil {
		log.Fatal(err)
	}

	if err := firewall.Init(iface, cfg); err != nil {
		log.Fatal(err)
	}
	log.Print("firewall configured")

	s.wg.Add(2)
	go s.handleInterface()
	go s.handleConnection()

	return s
}

func (s *Server) Wait() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ch:
		log.Print("keyboard interrupt")
	case err := <-s.errorCh:
		log.Print(err)
	}
}

func (s *Server) Shutdown() {
	close(s.quitCh)

	firewall.Shutdown(s.iface, s.cfg)
	s.iface.Close()
	s.conn.Close()

	close(s.toIfaceCh)
	close(s.toConnCh)

	s.wg.Wait()
}

func (s *Server) handleInterface() {
	defer s.wg.Done()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		for {
			select {
			case <-s.quitCh:
				return
			case pkt := <-s.toIfaceCh:
				if s.cfg.LogTraffic {
					log.Printf("sending through interface %v", pkt)
				}

				if _, err := s.iface.Write(pkt); err != nil {
					s.errorCh <- err
					return
				}
			}
		}
	}()

	buf := make([]byte, s.cfg.TunMTU)
	for {
		n, err := s.iface.Read(buf)
		if err != nil {
			select {
			case <-s.quitCh:
				return
			default:
				s.errorCh <- err
				return
			}
		}

		pkt := packet.Packet(buf[:n])
		s.toConnCh <- pkt
	}
}

func (s *Server) handleConnection() {
	defer s.wg.Done()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		for {
			select {
			case <-s.quitCh:
				return
			case pkt := <-s.toConnCh:
				if s.cfg.LogTraffic {
					log.Printf("sending through socket %v", pkt)
				}

				item, ok := s.clients.Get(pkt.Destination())
				if !ok {
					continue
				}
				addr := item.(*net.UDPAddr)

				data, err := crypt.Encrypt(pkt, s.key)
				if err != nil {
					log.Print(err)
					continue
				}

				s.conn.WriteToUDP(data, addr)
			}
		}
	}()

	buf := make([]byte, 2000)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.quitCh:
				return
			default:
				s.errorCh <- err
				return
			}
		}

		data, err := crypt.Decrypt(buf[:n], s.key)
		if err != nil {
			log.Print(err)
			continue
		}

		pkt := packet.Packet(data)
		if _, ok := s.clients.Get(pkt.Source()); !ok {
			s.clients.Set(pkt.Source(), addr, cache.DefaultExpiration)
		}

		if dst, ok := s.clients.Get(pkt.Destination()); ok && dst != "0.0.0.0" {
			s.toConnCh <- pkt
		} else {
			s.toIfaceCh <- pkt
		}
	}
}
