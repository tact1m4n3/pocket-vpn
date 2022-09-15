package tun

import (
	"errors"
	"runtime"
	"strconv"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func New() (*water.Interface, error) {
	return water.New(water.Config{DeviceType: water.TUN})
}

func Config(iface *water.Interface, cfg *config.Config) error {
	ip, ipnet, err := util.ParseCIDR(cfg.TunCIDR)
	if err != nil {
		return err
	}

	os := runtime.GOOS
	if os == "linux" {
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "mtu", strconv.Itoa(cfg.TunMTU))
		util.RunCommand("ip", "addr", "add", cfg.TunCIDR, "dev", iface.Name())
		util.RunCommand("ip", "link", "set", "dev", iface.Name(), "up")
		return nil
	} else if os == "darwin" {
		util.RunCommand("ifconfig", iface.Name(), cfg.TunCIDR, ip, "mtu", strconv.Itoa(cfg.TunMTU), "up")
		util.RunCommand("route", "add", ipnet, "-interface", iface.Name())
		return nil
	} else {
		return errors.New("platform not supported")
	}
}
