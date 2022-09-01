package tun

import (
	"errors"
	"net"
	"runtime"
	"strconv"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func New(cfg *config.Config) (*water.Interface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, err
	}

	if err := configInterface(iface, cfg); err != nil {
		return nil, err
	}

	return iface, nil
}

func configInterface(iface *water.Interface, cfg *config.Config) error {
	ip, ipnet, err := net.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		return err
	}

	os := runtime.GOOS
	if os == "linux" {
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(cfg.TunMTU))
		util.RunCommand("ip", "addr", "add", ipnet.String(), "dev", iface.Name())
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "up")
		return nil
	} else if os == "darwin" {
		util.RunCommand("ifconfig", iface.Name(), ipnet.String(), ip.String(), "mtu", strconv.Itoa(cfg.TunMTU), "up")
		util.RunCommand("route", "add", ipnet.String(), "-interface", iface.Name())
		return nil
	} else {
		return errors.New("platform not supported")
	}
}
