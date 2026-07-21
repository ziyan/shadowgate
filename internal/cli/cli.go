package cli

import (
	"context"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"

	"github.com/op/go-logging"
	"github.com/urfave/cli/v3"

	"github.com/ziyan/shadowgate/internal/client"
	"github.com/ziyan/shadowgate/internal/server"
	"github.com/ziyan/shadowgate/internal/tun"
	"github.com/ziyan/shadowgate/internal/version"
)

var log = logging.MustGetLogger("cli")

// tunnel is the common surface of the TCP and UDP client/server runners.
type tunnel interface {
	Interface() string
	Run(signaling chan os.Signal) error
	Close() error
}

// commonFlags are shared by the server and client subcommands. Both transports
// (TCP and UDP) are always active; there is no transport selection.
func commonFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "ifname", Usage: "tun interface name to create"},
		&cli.BoolFlag{Name: "persist", Usage: "keep the tun interface after exit"},
		&cli.StringFlag{Name: "password", Value: "", Usage: "shared secret used to encrypt the tunnel"},
		&cli.StringFlag{Name: "timeout", Value: "2s", Usage: "network operation timeout"},
		&cli.BoolFlag{Name: "compress", Usage: "tcp: Snappy-compress the stream (off by default)"},
		&cli.IntFlag{Name: "padding", Value: 256, Usage: "udp: maximum random padding bytes per datagram (0 disables)"},
		&cli.IntFlag{Name: "mtu", Value: 0, Usage: "tun interface MTU (0 = kernel default); lower it to keep UDP datagrams under the path MTU and avoid fragmentation"},
	}
}

// Run parses arguments and executes the shadowgate command, returning the
// process exit code.
func Run(arguments []string) int {
	command := &cli.Command{
		Name:                  "shadowgate",
		Usage:                 "a lightweight encrypted IP tunnel",
		Version:               version.UserAgent(),
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "loglevel",
				Value: "INFO",
				Usage: "logging verbosity (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)",
			},
		},
		Before: func(ctx context.Context, command *cli.Command) (context.Context, error) {
			logging.SetBackend(logging.NewBackendFormatter(
				logging.NewLogBackend(os.Stderr, "", 0),
				logging.MustStringFormatter(`%{color}%{time:2006-01-02T15:04:05.000Z07:00} [%{level:.4s}] [%{shortfile} %{shortfunc}] %{message}%{color:reset}`),
			))
			requested := command.String("loglevel")
			if level, err := logging.LogLevel(requested); err == nil {
				logging.SetLevel(level, "")
			}
			if logging.GetLevel("").String() != requested {
				log.Warningf("unknown log level: %s", requested)
			}
			log.Debugf("log level set to: %s", logging.GetLevel(""))
			return ctx, nil
		},
		Commands: []*cli.Command{
			serverCommand(),
			clientCommand(),
		},
	}

	if err := command.Run(context.Background(), arguments); err != nil {
		log.Errorf("%s", err)
		return 1
	}
	return 0
}

func serverCommand() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "Run in server mode",
		Flags: append(commonFlags(),
			&cli.StringFlag{Name: "ip", Value: "172.18.0.1/24", Usage: "tunnel address in CIDR notation"},
			&cli.StringFlag{Name: "listen", Value: ":3389", Usage: "address (TCP and UDP) to listen on"},
		),
		Action: func(ctx context.Context, command *cli.Command) error {
			ip, network, timeout, err := parseCommon(command)
			if err != nil {
				return err
			}

			runner, err := newServer(command, ip, network, timeout)
			if err != nil {
				log.Errorf("failed to start server: %s", err)
				return err
			}
			return runTunnel(runner, ip, network, command.Int("mtu"))
		},
	}
}

func clientCommand() *cli.Command {
	return &cli.Command{
		Name:  "client",
		Usage: "Run in client mode",
		Flags: append(commonFlags(),
			&cli.StringFlag{Name: "ip", Value: "172.18.0.2/24", Usage: "tunnel address in CIDR notation"},
			&cli.StringFlag{Name: "connect", Value: "127.0.0.1:3389", Usage: "server address to connect to (TCP and UDP)"},
		),
		Action: func(ctx context.Context, command *cli.Command) error {
			ip, network, timeout, err := parseCommon(command)
			if err != nil {
				return err
			}

			runner, err := newClient(command, ip, network, timeout)
			if err != nil {
				log.Errorf("failed to start client: %s", err)
				return err
			}
			return runTunnel(runner, ip, network, command.Int("mtu"))
		},
	}
}

// parseCommon parses the tunnel address and timeout shared by both subcommands.
func parseCommon(command *cli.Command) (net.IP, *net.IPNet, time.Duration, error) {
	ip, network, err := net.ParseCIDR(command.String("ip"))
	if err != nil {
		log.Errorf("failed to parse ip option: %s", err)
		return nil, nil, 0, err
	}
	timeout, err := time.ParseDuration(command.String("timeout"))
	if err != nil {
		log.Errorf("failed to parse timeout option: %s", err)
		return nil, nil, 0, err
	}
	return ip, network, timeout, nil
}

func newServer(command *cli.Command, ip net.IP, network *net.IPNet, timeout time.Duration) (tunnel, error) {
	device, err := tun.Open(command.String("ifname"), command.Bool("persist"))
	if err != nil {
		return nil, err
	}
	listen := command.String("listen")
	config := server.Config{
		TCPListen: listen,
		UDPListen: listen,
		Password:  []byte(command.String("password")),
		Compress:  command.Bool("compress"),
		Padding:   command.Int("padding"),
		Timeout:   timeout,
	}
	runner, err := server.NewServer(device, ip, network, config)
	if err != nil {
		_ = device.Close()
		return nil, err
	}
	return runner, nil
}

func newClient(command *cli.Command, ip net.IP, network *net.IPNet, timeout time.Duration) (tunnel, error) {
	device, err := tun.Open(command.String("ifname"), command.Bool("persist"))
	if err != nil {
		return nil, err
	}
	runner, err := client.NewClient(device, ip, network, command.String("connect"), []byte(command.String("password")), command.Bool("compress"), command.Int("padding"), timeout)
	if err != nil {
		_ = device.Close()
		return nil, err
	}
	return runner, nil
}

// runTunnel configures the interface and runs the tunnel until interrupted.
func runTunnel(runner tunnel, ip net.IP, network *net.IPNet, mtu int) error {
	defer func() {
		if err := runner.Close(); err != nil {
			log.Debugf("failed to close cleanly: %s", err)
		}
	}()

	configureInterface(runner.Interface(), ip, network, mtu)

	return runner.Run(interruptChannel())
}

// configureInterface assigns the tunnel address to the given interface, sets its
// MTU when one is requested, and brings it up. Failures are logged but not fatal
// so that the tunnel still runs when the interface was configured out of band.
func configureInterface(name string, ip net.IP, network *net.IPNet, mtu int) {
	address := &net.IPNet{IP: ip, Mask: network.Mask}
	if err := exec.Command("ip", "addr", "add", address.String(), "dev", name).Run(); err != nil {
		log.Warningf("failed to set addr on interface %s: %s", name, err)
	}
	if mtu > 0 {
		if err := exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)).Run(); err != nil {
			log.Warningf("failed to set mtu on interface %s: %s", name, err)
		}
	}
	if err := exec.Command("ip", "link", "set", "dev", name, "up").Run(); err != nil {
		log.Warningf("failed to bring up interface %s: %s", name, err)
	}
}

func interruptChannel() chan os.Signal {
	signaling := make(chan os.Signal, 1)
	signal.Notify(signaling, os.Interrupt)
	return signaling
}
