package util

import (
	"encoding/binary"
	"io"
	"net"
)

func ReadFromConn(conn net.Conn) ([]byte, error) {
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBuf))

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func WriteToConn(conn net.Conn, buf []byte) error {
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(buf)))
	if _, err := conn.Write(lengthBuf); err != nil {
		return err
	}

	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return nil
}
