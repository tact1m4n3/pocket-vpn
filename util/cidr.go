package util

import (
	"net"
)

func GetZeroIP(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ip.Mask(ipnet.Mask).String(), nil
}

func GenerateIPAddrs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ips := []string{}
	for curIP := ip.Mask(ipnet.Mask); ipnet.Contains(curIP); inc(curIP) {
		if !curIP.Equal(ip) && curIP[len(curIP)-1] != 0 && curIP[len(curIP)-1] != 255 {
			ips = append(ips, curIP.String())
		}
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
