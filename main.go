package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tact1m4n3/pocket-vpn/client"
	"github.com/tact1m4n3/pocket-vpn/config"
	"github.com/tact1m4n3/pocket-vpn/server"
	"github.com/tact1m4n3/pocket-vpn/util"
)

func main() {
	cfg := &config.Config{}

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ./pocket-vpn [options] [passphrase]")
		flag.PrintDefaults()
	}

	physIface, err := util.FindInterface()
	if err != nil {
		log.Fatal(err)
	}

	flag.BoolVar(&cfg.ServerMode, "S", false, "start vpn in server mode")
	flag.BoolVar(&cfg.LogTraffic, "L", false, "log all traffic to stdout")
	flag.BoolVar(&cfg.CaptureAll, "A", false, "capture all traffic")
	flag.StringVar(&cfg.TunCIDR, "c", "10.1.0.1/24", "tun cidr address")
	flag.IntVar(&cfg.TunMTU, "m", 1500, "tun mtu")
	flag.StringVar(&cfg.PhysIface, "i", physIface, "physical interface")
	flag.StringVar(&cfg.ServerAddr, "s", ":25566", "remote address")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "passphrase not specified")
		flag.Usage()
		os.Exit(1)
	}
	cfg.Passphrase = flag.Args()[0]

	if cfg.ServerMode {
		s := server.New(cfg)
		s.Wait()
		s.Shutdown()
	} else {
		c := client.New(cfg)
		c.Wait()
		c.Shutdown()
	}
}
