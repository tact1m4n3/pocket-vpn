package server

import (
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/crypt"
	"github.com/tact1m4n3/pocket-vpn/firewall"
	"github.com/tact1m4n3/pocket-vpn/handshake"
	"github.com/tact1m4n3/pocket-vpn/packet"
	"github.com/tact1m4n3/pocket-vpn/tun"
	"github.com/tact1m4n3/pocket-vpn/util"
)

type Server struct {
	cfg       *config.Config
	wg        *sync.WaitGroup
	quitCh    chan interface{}
	errorCh   chan error
	key       []byte
	salt      []byte
	listener  net.Listener
	iface     *water.Interface
	clients   map[string]net.Conn
	clientsMu *sync.RWMutex
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:       cfg,
		wg:        &sync.WaitGroup{},
		quitCh:    make(chan interface{}),
		errorCh:   make(chan error, 1),
		clients:   make(map[string]net.Conn),
		clientsMu: &sync.RWMutex{},
	}

	key, salt, err := crypt.GenerateKey(cfg.Passphrase, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated key based on passphrase")
	s.key, s.salt = key, salt

	listener, err := net.Listen("tcp", cfg.ServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening for connections on %v", listener.Addr())
	s.listener = listener

	_, ipnet, err := net.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	iface, err := tun.New(ipnet, cfg.TunMTU)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using tun interface %v", iface.Name())
	s.iface = iface

	if err := firewall.Init(iface, cfg); err != nil {
		log.Fatal(err)
	}
	log.Print("firewall configured")

	s.wg.Add(2)
	go s.listen()
	go s.handleInterface()

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
	s.listener.Close()

	s.wg.Wait()
}

func (s *Server) listen() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quitCh:
				return
			default:
				s.errorCh <- err
				return
			}
		}

		s.wg.Add(1)
		go func() {
			s.handleConnection(conn)
			s.wg.Done()
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("new connection from %v", conn.RemoteAddr())
	defer log.Printf("closed connection to %v", conn.RemoteAddr())

	hinfo := &handshake.Info{Salt: s.salt, Key: s.key, IP: netip.MustParseAddr("10.1.0.2")}
	if err := handshake.ServerWithClient(conn, hinfo); err != nil {
		log.Print(err)
		return
	}

ReadLoop:
	for {
		select {
		case <-s.quitCh:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			data, err := util.ReadFromConn(conn)
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue ReadLoop
				} else if err == io.EOF {
					return
				} else {
					log.Print(err)
					return
				}
			}

			data, err = crypt.Decrypt(data, s.key)
			if err != nil {
				log.Print(err)
				continue
			}
			pkt := packet.Packet(data)

			s.clientsMu.Lock()
			s.clients[string(pkt.Source())] = conn
			s.clientsMu.Unlock()

			if s.cfg.LogTraffic {
				log.Printf("received %v", pkt)
			}

			if _, err := s.iface.Write(pkt); err != nil {
				select {
				case <-s.quitCh:
					return
				default:
					log.Print(err)
					return
				}
			}
		}
	}
}

func (s *Server) handleInterface() {
	defer s.wg.Done()

	buf := make([]byte, 2000)
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

		s.clientsMu.RLock()
		conn := s.clients[string(pkt.Destination())]
		s.clientsMu.RUnlock()
		if conn == nil {
			continue
		}

		if s.cfg.LogTraffic {
			log.Printf("sending %v", pkt)
		}

		data, err := crypt.Encrypt(pkt, s.key)
		if err != nil {
			log.Print(err)
			continue
		}

		if err := util.WriteToConn(conn, data); err != nil {
			delete(s.clients, string(pkt.Destination()))
		}
	}
}
