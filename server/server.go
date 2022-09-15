package server

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

	key []byte
	ip  string

	clients map[string]*net.UDPAddr

	iface *water.Interface
	conn  *net.UDPConn
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg: cfg,

		wg:      &sync.WaitGroup{},
		quitCh:  make(chan struct{}),
		errorCh: make(chan error, 1),

		clients: make(map[string]*net.UDPAddr),
	}

	key, err := crypt.GenerateKey(cfg.Passphrase)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated key based on passphrase")
	s.key = key

	ip, _, err := util.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using ip %v", ip)
	s.ip = ip

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

	s.wg.Wait()
}

func (s *Server) handleInterface() {
	defer s.wg.Done()

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
		if s.cfg.LogTraffic {
			log.Printf("sending %v", pkt)
		}
		addr := s.clients[pkt.Destination()]
		if addr == nil {
			continue
		}

		data, err := crypt.Encrypt(pkt, s.key)
		if err != nil {
			log.Print(err)
			continue
		}

		s.conn.WriteToUDP(data, addr)
	}
}

func (s *Server) handleConnection() {
	defer s.wg.Done()

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
		if s.cfg.LogTraffic {
			log.Printf("received %v", pkt)
		}
		s.clients[pkt.Source()] = addr

		if _, err := s.iface.Write(pkt); err != nil {
			s.errorCh <- err
			return
		}
	}
}
