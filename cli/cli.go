package cli

import (
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/op/go-logging"
	"github.com/urfave/cli"

	"github.com/ziyan/shadowgate/client"
	"github.com/ziyan/shadowgate/server"
)

var log = logging.MustGetLogger("cli")

func Run(args []string) {

	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Name = "ShadowGate"
	app.Version = "0.1.0"
	app.Usage = "ShadowGate"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "loglevel",
			Value: "INFO",
		},
	}

	app.Before = func(c *cli.Context) error {
		logging.SetBackend(logging.NewBackendFormatter(
			logging.NewLogBackend(os.Stderr, "", 0),
			logging.MustStringFormatter(`%{color}%{time:2006-01-02T15:04:05.000Z07:00} [%{level:.4s}] [%{shortfile} %{shortfunc}] %{message}%{color:reset}`),
		))
		if level, err := logging.LogLevel(c.String("loglevel")); err == nil {
			logging.SetLevel(level, "")
		}
		if logging.GetLevel("").String() != c.String("loglevel") {
			log.Warningf("unknown log level: %s", c.String("loglevel"))
		}
		log.Debugf("log level set to: %s", logging.GetLevel(""))
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:  "server",
			Usage: "Run in server mode",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name",
					Value: "sg0",
				},
				cli.BoolFlag{
					Name: "persist",
				},
				cli.StringFlag{
					Name:  "ip",
					Value: "172.18.0.1/24",
				},
				cli.StringFlag{
					Name:  "listen",
					Value: ":3389",
				},
				cli.StringFlag{
					Name:  "password",
					Value: "",
				},
				cli.StringFlag{
					Name:  "timeout",
					Value: "2s",
				},
			},
			Action: func(c *cli.Context) error {
				ip, network, err := net.ParseCIDR(c.String("ip"))
				if err != nil {
					log.Errorf("failed to parse ip option: %s", err)
					return err
				}

				timeout, err := time.ParseDuration(c.String("timeout"))
				if err != nil {
					log.Errorf("failed to parse timeout option: %s", err)
					return err
				}

				server, err := server.NewServer(c.String("name"), c.Bool("persist"), ip, network, c.String("listen"), []byte(c.String("password")), timeout)
				if err != nil {
					log.Errorf("failed to start server: %s", err)
					return err
				}
				defer server.Close()

				// setup the interface
				ipnet := &net.IPNet{ip, network.Mask}
				if err := exec.Command("ip", "addr", "add", ipnet.String(), "dev", server.Name()).Run(); err != nil {
					log.Warningf("failed to set addr on interface %s: %s", server.Name(), err)
				}
				if err := exec.Command("ip", "link", "set", "dev", server.Name(), "up").Run(); err != nil {
					log.Warningf("failed to bring up interface %s: %s", server.Name(), err)
				}

				signaling := make(chan os.Signal, 1)
				signal.Notify(signaling, os.Interrupt)
				return server.Run(signaling)
			},
		},
		{
			Name:  "client",
			Usage: "Run in client mode",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name",
					Value: "sg0",
				},
				cli.BoolFlag{
					Name: "persist",
				},
				cli.StringFlag{
					Name:  "ip",
					Value: "172.18.0.2/24",
				},
				cli.StringFlag{
					Name:  "connect",
					Value: "127.0.0.1:3389",
				},
				cli.StringFlag{
					Name:  "password",
					Value: "",
				},
				cli.StringFlag{
					Name:  "timeout",
					Value: "2s",
				},
			},
			Action: func(c *cli.Context) error {

				ip, network, err := net.ParseCIDR(c.String("ip"))
				if err != nil {
					log.Errorf("failed to parse ip option: %s", err)
					return err
				}

				timeout, err := time.ParseDuration(c.String("timeout"))
				if err != nil {
					log.Errorf("failed to parse timeout option: %s", err)
					return err
				}

				client, err := client.NewClient(c.String("name"), c.Bool("persist"), ip, network, c.String("connect"), []byte(c.String("password")), timeout)
				if err != nil {
					log.Errorf("failed to start client: %s", err)
					return err
				}
				defer client.Close()

				// setup the interface
				ipnet := &net.IPNet{ip, network.Mask}
				if err := exec.Command("ip", "addr", "add", ipnet.String(), "dev", client.Name()).Run(); err != nil {
					log.Warningf("failed to set addr on interface %s: %s", client.Name(), err)
				}
				if err := exec.Command("ip", "link", "set", "dev", client.Name(), "up").Run(); err != nil {
					log.Warningf("failed to bring up interface %s: %s", client.Name(), err)
				}

				signaling := make(chan os.Signal, 1)
				signal.Notify(signaling, os.Interrupt)
				return client.Run(signaling)
			},
		},
	}

	app.Run(args)
}
