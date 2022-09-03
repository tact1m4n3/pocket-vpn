package server

import (
	"io"
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
	ipAddrs   []string
	ipAddrsMu *sync.RWMutex
	clients   map[string]net.Conn
	clientsMu *sync.RWMutex
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:       cfg,
		wg:        &sync.WaitGroup{},
		quitCh:    make(chan interface{}),
		errorCh:   make(chan error, 1),
		ipAddrsMu: &sync.RWMutex{},
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

	iface, err := tun.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("using tun interface %v", iface.Name())
	s.iface = iface

	if err := firewall.Init(iface, cfg); err != nil {
		log.Fatal(err)
	}
	log.Print("firewall configured")

	ipAddrs, err := util.GenerateIPAddrs(cfg.TunCIDR)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("generated client ip addresses")
	s.ipAddrs = ipAddrs

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

	if len(s.ipAddrs) == 0 {
		log.Printf("all available ip addresses used... disconnecting client")
	}
	s.ipAddrsMu.Lock()
	ip := s.ipAddrs[0]
	s.ipAddrs = s.ipAddrs[1:]
	s.ipAddrsMu.Unlock()
	defer func() {
		s.ipAddrsMu.Lock()
		s.ipAddrs = append(s.ipAddrs, ip)
		s.ipAddrsMu.Unlock()
	}()

	s.clientsMu.Lock()
	s.clients[ip] = conn
	s.clientsMu.Unlock()
	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, ip)
		s.clientsMu.Unlock()
	}()

	hinfo := &handshake.Info{Salt: s.salt, Key: s.key, IP: ip}
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
			encrypted, err := util.ReadFromConn(conn)
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

			plaintext, err := crypt.Decrypt(encrypted, s.key)
			if err != nil {
				log.Print(err)
				continue
			}
			pkt := packet.Packet(plaintext)

			if pkt.Source() != ip {
				continue
			}

			if s.cfg.LogTraffic {
				log.Printf("sending %v", pkt)
			}

			dstConn := s.getConnection(pkt.Destination())
			if dstConn != nil {
				util.WriteToConn(dstConn, encrypted)
			} else {
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

		conn := s.getConnection(pkt.Destination())
		if conn == nil {
			continue
		}

		if s.cfg.LogTraffic {
			log.Printf("received %v", pkt)
		}

		data, err := crypt.Encrypt(pkt, s.key)
		if err != nil {
			log.Print(err)
			continue
		}

		util.WriteToConn(conn, data)
	}
}

func (s *Server) getConnection(ip string) net.Conn {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	return s.clients[ip]
}
