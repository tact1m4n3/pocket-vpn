package util

import (
	"errors"
	"net"
	"strings"
)

func FindInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp == 1 && isPhysicalInterface(iface) {
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				return iface.Name, nil
			}
		}
	}

	return "", errors.New("no interface found")
}

func isPhysicalInterface(iface net.Interface) bool {
	prefixes := []string{"en", "eth"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			return true
		}
	}
	return false
}
