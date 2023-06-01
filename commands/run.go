package commands

import (
	"os"
	"time"

	"agora-app/agora"
	"agora-app/config"
	"agora-app/log"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

type AgoraApp struct {
	ServiceName      string
	WorkingDirectory string
	User             string
	Config           string
	Syslog           bool
	exit             chan struct{}
}

var logger service.Logger

func getCwd() string {
	path, err := os.Getwd()
	if err != nil {
		return ""
	}
	return path
}

func (app *AgoraApp) Start(s service.Service) error {
	if service.Interactive() {
		logrus.Info("Running in terminal.")
	} else {
		logrus.Info("Running under service manager.")
	}
	app.exit = make(chan struct{})

	if app.WorkingDirectory != "" {
		os.Chdir(app.WorkingDirectory)
	}
	logrus.Info("Current working directory: ", getCwd())

	// Start should not block. Do the actual work async.
	go app.run()
	return nil
}
func (app *AgoraApp) run() error {
	conf, err := config.GetConf(app.Config, true)
	if err != nil {
		logrus.Fatal("Cannot read the config file: ", err)
	}
	agora.HandleNoCertificateCheck(conf.General.NoCertificateCheck)
	success, err := agora.CheckConnection(conf.Agora.Url, conf.Agora.ApiKey)
	if !success {
		logrus.Fatal("Cannot connect to Agora: ", err)
	}
	ws, err := agora.StartWebSocket(conf)
	if err != nil {
		logrus.Fatal("Cannot connect the websocket: ", err)
	}

	connected := true

	logrus.Info("Running and connected to Agora:")
	logrus.Info("    Version      : ", agora.AppVersion)
	logrus.Info("    Agora URL    : ", conf.Agora.Url)
	logrus.Info("    Download path: ", conf.General.BasePath)
	logrus.Info("    UID          : ", conf.General.Uid)
	for {
		select {
		case <-app.exit:
			return nil
		default:
			msg, err := agora.WsListen(ws)
			if err != nil {
				if connected {
					logrus.Error("Error receiving message: ", err)
				}
				ws_try, err_connect := agora.Connect(conf)
				if err_connect != nil {
					if connected {
						logrus.Error("Disconnected from the Agora server. Trying to reconnect periodically")
						connected = false
					}
					time.Sleep(2 * time.Second)
				} else {
					connected = true
					ws = ws_try
					logrus.Info("Reconnected to Agora")
				}
			} else {
				logrus.Debugf("Received message: %s.\n", msg)
				go agora.WsProcess(ws, msg, conf)
			}
		}
	}
}
func (app *AgoraApp) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	logger.Info("Stopping!")
	close(app.exit)
	return nil
}

func (app *AgoraApp) execute() {
	options := make(service.KeyValue)
	options["Restart"] = "on-success"
	options["SuccessExitStatus"] = "1 2 8 SIGKILL"
	svcConfig := &service.Config{
		Name:        app.ServiceName,
		DisplayName: "Agora App",
		Description: "Agora helper app for downloading files and running local tasks",
		Dependencies: []string{
			"Requires=network.target",
			"After=network-online.target syslog.target"},
		Option: options,
	}

	s, err := service.New(app, svcConfig)
	if err != nil {
		logrus.Fatal(err)
	}

	if app.Syslog {
		log.SetSystemLogger(logrus.StandardLogger(), s)
	}

	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		logrus.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				logrus.Print(err)
			}
		}
	}()

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}

func init() {
	command := cli.Command{
		Name:  "run",
		Usage: "run app",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "service",
				Value: "agora-app",
				Usage: "Use a different name for the service",
			},
			&cli.StringFlag{
				Name:  "working-directory",
				Value: getCwd(),
				Usage: "Specify custom working directory",
			},
			&cli.StringFlag{
				Name:  "user",
				Value: "",
				Usage: "Use specific user to execute shell scripts",
			},
			&cli.StringFlag{
				Name:  "config",
				Value: config.GetDefaultConfigFile(),
				Usage: "Path to the config file",
			},
			&cli.BoolFlag{
				Name:  "syslog",
				Value: false,
				Usage: "Log to system service logger",
			},
		},
		Action: func(c *cli.Context) error {
			app := &AgoraApp{ServiceName: c.String("service"),
				WorkingDirectory: c.String("working-directory"),
				User:             c.String("user"),
				Config:           c.String("config"),
				Syslog:           c.Bool("syslog")}
			app.execute()
			os.Exit(0)
			return nil
		},
	}

	RegisterCommand(&command)
}
