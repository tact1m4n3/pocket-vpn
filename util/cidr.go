package util

import (
	"net"
)

func ParseCIDR(cidr string) (string, string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	return ip.String(), ipnet.String(), nil
}
