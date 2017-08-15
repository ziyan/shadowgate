package cli

import (
	"os"

	"github.com/op/go-logging"
	"github.com/urfave/cli"
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
			Value: "DEBUG",
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
					Name:  "listen",
					Value: ":3389",
				},
				cli.StringFlag{
					Name:  "password",
					Value: "",
				},
				cli.StringFlag{
					Name:  "ip",
					Value: "172.18.0.1/24",
				},
			},
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "client",
			Usage: "Run in client mode",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "connect",
					Value: "127.0.0.1:3389",
				},
				cli.StringFlag{
					Name:  "password",
					Value: "",
				},
				cli.StringFlag{
					Name:  "ip",
					Value: "172.18.0.2/24",
				},
			},
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	}

	app.Run(args)
}
