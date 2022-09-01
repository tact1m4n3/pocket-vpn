package routes

import (
	"errors"
	"runtime"

	"github.com/songgao/water"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func Init(iface *water.Interface, cfg *config.Config) error {
	os := runtime.GOOS
	if os == "linux" {
		if cfg.CaptureAll {
			util.RunCommand("ip", "route", "add", "0/1", "dev", iface.Name())
			util.RunCommand("ip", "route", "add", "128/1", "dev", iface.Name())
		} else {
			util.RunCommand("ip", "route", "add", "8.8.8.8", "dev", iface.Name())
		}
		return nil
	} else if os == "darwin" {
		if cfg.CaptureAll {
			util.RunCommand("route", "add", "0/1", "-interface", iface.Name())
			util.RunCommand("route", "add", "128/1", "-interface", iface.Name())
		} else {
			util.RunCommand("route", "add", "8.8.8.8", "-interface", iface.Name())
		}
		return nil
	} else {
		return errors.New("platform not supported")
	}
}

func Shutdown(iface *water.Interface, cfg *config.Config) error {
	os := runtime.GOOS
	if os == "linux" {
		if cfg.CaptureAll {
			util.RunCommand("ip", "route", "delete", "0/1", "dev", iface.Name())
			util.RunCommand("ip", "route", "delete", "128/1", "dev", iface.Name())
		} else {
			util.RunCommand("ip", "route", "delete", "8.8.8.8", "dev", iface.Name())
		}
		return nil
	} else if os == "darwin" {
		if cfg.CaptureAll {
			util.RunCommand("route", "delete", "0/1", "-interface", iface.Name())
			util.RunCommand("route", "delete", "128/1", "-interface", iface.Name())
		} else {
			util.RunCommand("route", "delete", "8.8.8.8", "-interface", iface.Name())
		}
		return nil
	} else {
		return errors.New("platform not supported")
	}
}
