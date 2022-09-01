package tun

import (
	"errors"
	"net"
	"runtime"
	"strconv"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func New(ipnet *net.IPNet, mtu int) (*water.Interface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, err
	}

	if err := configInterface(iface, ipnet, mtu); err != nil {
		return nil, err
	}

	return iface, nil
}

func configInterface(iface *water.Interface, ipnet *net.IPNet, mtu int) error {
	os := runtime.GOOS
	if os == "linux" {
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(mtu))
		util.RunCommand("ip", "addr", "add", ipnet.String(), "dev", iface.Name())
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "up")
		return nil
	} else if os == "darwin" {
		util.RunCommand("ifconfig", iface.Name(), ipnet.String(), ipnet.IP.String(), "mtu", strconv.Itoa(mtu), "up")
		return nil
	} else {
		return errors.New("platform not supported")
	}
}
