package handshake

import (
	"errors"
	"io"
	"net"

	"github.com/tact1m4n3/pocket-vpn/crypt"
	"github.com/tact1m4n3/pocket-vpn/util"
)

const AUTH_MSG = "AUTH_MSG"

type Info struct {
	Salt []byte
	Key  []byte
	IP   net.IP
}

func ClientWithServer(conn net.Conn, passphrase string) (*Info, error) {
	info := &Info{}

	salt := make([]byte, 8)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, err
	}
	info.Salt = salt

	key, _, err := crypt.GenerateKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	info.Key = key

	if !clientAuth(conn, key) {
		return nil, errors.New("authentication failed")
	}

	ip := make([]byte, 16)
	n, err := conn.Read(ip)
	if err != nil {
		return nil, err
	}
	info.IP = net.IP(ip[:n])

	return info, nil
}

func ServerWithClient(conn net.Conn, info *Info) error {
	if _, err := conn.Write(info.Salt); err != nil {
		return err
	}

	if !serverAuth(conn, info.Key) {
		return errors.New("client authentication failed")
	}

	if _, err := conn.Write(info.IP); err != nil {
		return err
	}

	return nil
}

func clientAuth(conn net.Conn, key []byte) bool {
	data, err := crypt.Encrypt([]byte(AUTH_MSG), key)
	if err != nil {
		return false
	}
	if err := util.WriteToConn(conn, data); err != nil {
		return false
	}

	status := []byte{0}
	if _, err := conn.Read(status); err != nil {
		return false
	}
	return status[0] == 1
}

func serverAuth(conn net.Conn, key []byte) bool {
	data, err := util.ReadFromConn(conn)
	if err != nil {
		return false
	}

	data, err = crypt.Decrypt(data, key)
	if err != nil {
		return false
	}
	if string(data) != AUTH_MSG {
		conn.Write([]byte{0})
		return false
	}

	if _, err := conn.Write([]byte{1}); err != nil {
		return false
	}
	return true
}
