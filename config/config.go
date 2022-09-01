package config

type Config struct {
	ServerMode bool
	LogTraffic bool
	CaptureAll bool
	TunCIDR    string
	TunMTU     int
	PhysIface  string
	ServerAddr string
	Passphrase string
}
