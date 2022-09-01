package firewall

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func Init(iface *water.Interface, cfg *config.Config) error {
	os := runtime.GOOS
	if os == "linux" {
		util.RunCommand("sysctl", "-w", "net.ipv4.ip_forward=1")
		util.RunCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", cfg.PhysIface, "-j", "MASQUERADE")
		util.RunCommand("iptables", "-A", "FORWARD", "-i", iface.Name(), "-j", "ACCEPT")
		return nil
	} else if os == "darwin" {
		util.RunCommand("sysctl", "-w", "net.inet.ip.forwarding=1")
		util.RunCommand("bash", "-c", fmt.Sprintf(
			"echo 'nat on %v inet from %v:network to any -> (%v)' | pfctl -v -ef -",
			cfg.PhysIface, iface.Name(), cfg.PhysIface,
		))
		return nil
	} else {
		return errors.New("platform not supported")
	}
}

func Shutdown(iface *water.Interface, cfg *config.Config) error {
	os := runtime.GOOS
	if os == "linux" {
		util.RunCommand("iptables", "-D", "FORWARD", "-i", iface.Name(), "-j", "ACCEPT")
		util.RunCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", cfg.PhysIface, "-j", "MASQUERADE")
		util.RunCommand("sysctl", "-w", "net.ipv4.ip_forward=0")
		return nil
	} else if os == "darwin" {
		util.RunCommand("pfctl", "-d")
		util.RunCommand("sysctl", "-w", "net.inet.ip.forwarding=0")
		return nil
	} else {
		return errors.New("platform not supported")
	}
}
