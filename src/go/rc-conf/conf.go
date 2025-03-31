package rcconf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"
)

type Config struct {
	locale           string
	timezone         string
	keymap           string
	hostname         string
	enabled_daemons  []string
	disabled_daemons []string
	netconfig        NetworkConfig
}

type NetworkConfig struct {
	net_interface string
	address       string
	netmask       string
	broadcast     string
	gateway       string
}

func netmaskToCIDR(netmask string) (int, error) {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0, fmt.Errorf("invalid netmask: %s", netmask)
	}

	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", netmask)
	}

	cidr := 0
	for _, b := range ip {
		for b > 0 {
			cidr += int(b & 1)
			b >>= 1
		}
	}

	return cidr, nil
}

func ParseConfig() Config {
	config_file, ok := os.LookupEnv("RC_CONF")
	if !ok {
		config_file = "/etc/rc.conf"
	}

	file, err := os.Open(config_file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cfg := Config{}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "=") || strings.HasPrefix(line, "#") {
			continue
		}

		// Should all be well formed configs
		parts := strings.Split(line, "=")
		if len(parts) > 2 {
			fmt.Fprintln(os.Stderr, "not well formed config option %v", line)
			continue
		}

		key := parts[0]
		value := parts[1]
		value = strings.TrimLeft(value, "\"")
		value = strings.TrimRight(value, "\"")

		switch key {
		case "LOCALE":
			cfg.locale = value
			break
		case "TIMEZONE":
			cfg.timezone = value
			break
		case "KEYMAP":
			cfg.keymap = value
			break
		case "HOSTNAME":
			cfg.hostname = value
			break
		case "interface":
			cfg.netconfig.net_interface = value
			break
		case "address":
			cfg.netconfig.address = value
			break
		case "netmask":
			cfg.netconfig.netmask = value
			break
		case "broadcast":
			cfg.netconfig.broadcast = value
			break
		case "gateway":
			cfg.netconfig.gateway = value
			break
		case "DAEMONS":
			// Strip off bash array declaration
			value = strings.TrimRight(value, ")")
			value = strings.TrimLeft(value, "(")
			services := strings.Split(value, " ")
			for _, v := range services {
				// lol, users think we would background services for them, we let systemd take care of that...
				if strings.HasPrefix(v, "@") {
					cfg.enabled_daemons = append(cfg.enabled_daemons, strings.TrimLeft(v, "@"))
				} else if strings.HasPrefix(v, "!") {
					cfg.disabled_daemons = append(cfg.disabled_daemons, strings.TrimLeft(v, "!"))
				} else {
					cfg.enabled_daemons = append(cfg.enabled_daemons, v)
				}
			}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	return cfg
}

func systemd_exec(comand string, arg ...string) {
	cmd := exec.Command(comand, arg...)
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("could not run command: ", err, out)
	}
}

func Enable(cfg *Config) {
	fmt.Printf("%v\n", cfg)
	if cfg.locale != "" {
		systemd_exec("localectl", "set-locale", cfg.locale)
	}
	if cfg.keymap != "" {
		systemd_exec("localectl", "set-keymap", cfg.keymap)
	}
	if cfg.timezone != "" {
		systemd_exec("timedatectl", "set-timezone", cfg.timezone)
	}
	if cfg.hostname != "" {
		systemd_exec("hostnamectl", "hostname", cfg.hostname)
	}

	conn, err := dbus.NewSystemdConnectionContext(context.Background())
	if err != nil {
		fmt.Printf("cannot connect to system bus")
		return
	}
	defer conn.Close()

	if len(cfg.disabled_daemons) != 0 {
		_, err = conn.DisableUnitFilesContext(context.Background(), cfg.disabled_daemons, false)
		if err != nil {
			fmt.Printf("unable to disable daemons=%v", cfg.disabled_daemons)
			return
		}
	}

	if len(cfg.enabled_daemons) != 0 {
		_, _, err = conn.EnableUnitFilesContext(context.Background(), cfg.enabled_daemons, false, false)
		if err != nil {
			fmt.Printf("unable to enable daemons=%v", cfg.enabled_daemons)
			return
		}
	}

	// Networking
	if cfg.netconfig.net_interface != "" {
		networkd_file, err := os.Create("/etc/systemd/network/20-rc-conf.network")
		if err != nil {
			return
		}

		defer networkd_file.Close()
		config_complete := false
		network_cfg := fmt.Sprintf("[Match]\nName=%s\n\n[Network]\n", cfg.netconfig.net_interface)

		if cfg.netconfig.address == "" { // DHCP
			network_cfg += "DHCP=yes\n"
			config_complete = true
		} else if cfg.netconfig.gateway != "" && cfg.netconfig.netmask != "" { // static
			netmask, err := netmaskToCIDR(cfg.netconfig.netmask)
			if err == nil {
				network_cfg += fmt.Sprintf("Address=%s/%d\nGateway=%s\n", cfg.netconfig.address, netmask, cfg.netconfig.gateway)
				if cfg.netconfig.broadcast != "" {
					network_cfg += fmt.Sprintf("Broadcast=%s\n", cfg.netconfig.broadcast)
				}
				config_complete = true
			}
		}

		if config_complete {
			networkd_file.Write([]byte(network_cfg))

			err = conn.ReloadContext(context.Background())
			if err != nil {
				fmt.Printf("unable to daemon reload")
				return
			}

			services := []string{"systemd-networkd"}
			_, _, err = conn.EnableUnitFilesContext(context.Background(), services, false, false)
			if err != nil {
				fmt.Printf("cannot enable systemd-networkd")
			}

			// might already enabled, so we restart anyway
			reschan := make(chan string)
			_, err = conn.RestartUnitContext(context.Background(), "systemd-networkd", "replace", reschan)
			if err != nil {
				fmt.Printf("cannot restart systemd-networkd")
			}

			job := <-reschan
			if job != "done" {
				fmt.Printf("check systemd-networkd logs..")
			}
		}
	}
}
