package commands

import (
	"agora-app/config"
	"fmt"
	"os"
	"runtime"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	defaultServiceName = "agora-app"
	defaultDescription = "Agora App"
)

const (
	osTypeLinux   = "linux"
	osTypeDarwin  = "darwin"
	osTypeWindows = "windows"
)

type NullService struct {
}

func (n *NullService) Start(s service.Service) error {
	return nil
}

func (n *NullService) Stop(s service.Service) error {
	return nil
}

func getCurrentWorkingDirectory() string {
	dir, err := os.Getwd()
	if err == nil {
		return dir
	}
	return ""
}

func setupOSServiceConfig(c *cli.Context, config *service.Config) {
	config.Option = service.KeyValue{
		"Password": c.String("password"),
	}
	config.UserName = c.String("user")
}

func runServiceInstall(s service.Service, c *cli.Context) error {
	// create the config file if it doesn't exist
	if config_file := c.String("config"); config_file != "" {
		_, err := config.GetConf(config_file, false)
		if err != nil {
			logrus.Fatal("Cannot read the config file")
		}
	}

	return service.Control(s, "install")
}

func runServiceStatus(displayName string, s service.Service) {
	status, err := s.Status()

	description := ""
	switch status {
	case service.StatusRunning:
		description = "Service is running"
	case service.StatusStopped:
		description = "Service has stopped"
	default:
		description = "Service status unknown"
		if err != nil {
			description = err.Error()
		}
	}

	if status != service.StatusRunning {
		fmt.Fprintf(os.Stderr, "%s: %s\n", displayName, description)
		os.Exit(1)
	}

	fmt.Printf("%s: %s\n", displayName, description)
}

func GetServiceArguments(c *cli.Context) (arguments []string) {
	if wd := c.String("working-directory"); wd != "" {
		arguments = append(arguments, "--working-directory", wd)
	}

	if config := c.String("config"); config != "" {
		arguments = append(arguments, "--config", config)
	}

	if sn := c.String("service"); sn != "" {
		arguments = append(arguments, "--service", sn)
	}

	// syslogging doesn't make sense for systemd systems as those log straight to journald
	syslog := !c.IsSet("syslog") || c.Bool("syslog")
	if service.Platform() == "linux-systemd" && !c.IsSet("syslog") {
		syslog = false
	}

	if syslog {
		arguments = append(arguments, "--syslog")
	}

	return
}

func createServiceConfig(c *cli.Context) *service.Config {
	config := &service.Config{
		Name:        c.String("service"),
		DisplayName: c.String("service"),
		Description: defaultDescription,
		Arguments:   append([]string{"run"}, GetServiceArguments(c)...),
	}

	// setup os specific service config
	setupOSServiceConfig(c, config)

	return config
}

func RunServiceControl(c *cli.Context) error {
	svcConfig := createServiceConfig(c)

	s, err := service.New(&NullService{}, svcConfig)
	if err == service.ErrNoServiceSystemDetected {
		logrus.Fatal("No service system detected. Some features may not work!")
		os.Exit(1)
	}

	if err != nil {
		logrus.Fatal(err)
		return err
	}

	switch c.Command.Name {
	case "install":
		err = runServiceInstall(s, c)
	case "status":
		runServiceStatus(svcConfig.DisplayName, s)
	default:
		err = service.Control(s, c.Command.Name)
	}

	if err != nil {
		logrus.Fatal(err)
		return err
	}
	return nil
}

func getFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "service, n",
			Value: defaultServiceName,
			Usage: "Specify service name to use",
		},
	}
}

func getInstallFlags() []cli.Flag {
	installFlags := getFlags()
	installFlags = append(
		installFlags,
		&cli.StringFlag{
			Name:  "working-directory, d",
			Value: getCurrentWorkingDirectory(),
			Usage: "Specify custom root directory where all data are stored",
		},
		&cli.StringFlag{
			Name:  "config, c",
			Value: config.GetDefaultConfigFile(),
			Usage: "Specify custom config file",
		},
		&cli.BoolFlag{
			Name:  "syslog",
			Usage: "Setup system logging integration",
		},
	)

	if runtime.GOOS == osTypeWindows {
		installFlags = append(
			installFlags,
			&cli.StringFlag{
				Name:  "user, u",
				Value: "",
				Usage: "Specify user-name to secure the runner",
			},
			&cli.StringFlag{
				Name:  "password, p",
				Value: "",
				Usage: "Specify user password to install service (required)",
			})
	} else if os.Getuid() == 0 {
		installFlags = append(installFlags, &cli.StringFlag{
			Name:  "user, u",
			Value: "",
			Usage: "Specify user-name to secure the runner",
		})
	}

	return installFlags
}

func init() {
	flags := getFlags()
	installFlags := getInstallFlags()

	RegisterCommand(&cli.Command{
		Name:   "install",
		Usage:  "install service",
		Action: RunServiceControl,
		Flags:  installFlags,
	})
	RegisterCommand(&cli.Command{
		Name:   "uninstall",
		Usage:  "uninstall service",
		Action: RunServiceControl,
		Flags:  flags,
	})
	RegisterCommand(&cli.Command{
		Name:   "start",
		Usage:  "start service",
		Action: RunServiceControl,
		Flags:  flags,
	})
	RegisterCommand(&cli.Command{
		Name:   "stop",
		Usage:  "stop service",
		Action: RunServiceControl,
		Flags:  flags,
	})
	RegisterCommand(&cli.Command{
		Name:   "restart",
		Usage:  "restart service",
		Action: RunServiceControl,
		Flags:  flags,
	})
	RegisterCommand(&cli.Command{
		Name:   "status",
		Usage:  "get status of a service",
		Action: RunServiceControl,
		Flags:  flags,
	})
}
