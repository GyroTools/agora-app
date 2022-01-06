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

const sysvDebianScript = `#! /bin/bash

### BEGIN INIT INFO
# Provides:          {{.Path}}
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: {{.DisplayName}}
# Description:       {{.Description}}
### END INIT INFO

DESC="{{.Description}}"
USER="{{.UserName}}"
NAME="{{.Name}}"
PIDFILE="/var/run/$NAME.pid"

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Define LSB log_* functions.
. /lib/lsb/init-functions

## Check to see if we are running as root first.
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root"
    exit 1
fi

do_start() {
  start-stop-daemon --start \
    {{if .ChRoot}}--chroot {{.ChRoot|cmd}}{{end}} \
    {{if .WorkingDirectory}}--chdir {{.WorkingDirectory|cmd}}{{end}} \
    {{if .UserName}} --chuid {{.UserName|cmd}}{{end}} \
    --pidfile "$PIDFILE" \
    --background \
    --make-pidfile \
    --exec {{.Path}} -- {{range .Arguments}} {{.|cmd}}{{end}}
}

do_stop() {
  start-stop-daemon --stop \
    {{if .UserName}} --chuid {{.UserName|cmd}}{{end}} \
    --pidfile "$PIDFILE" \
    --quiet
}

case "$1" in
  start)
    log_daemon_msg "Starting $DESC"
    do_start
    log_end_msg $?
    ;;
  stop)
    log_daemon_msg "Stopping $DESC"
    do_stop
    log_end_msg $?
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  status)
    status_of_proc -p "$PIDFILE" "$DAEMON" "$DESC"
    ;;
  *)
    echo "Usage: sudo service $0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac

exit 0
`

const sysvRedhatScript = `#!/bin/sh
# For RedHat and cousins:
# chkconfig: - 99 01
# description: {{.Description}}
# processname: {{.Path}}

# Source function library.
. /etc/rc.d/init.d/functions

name="{{.Name}}"
desc="{{.Description}}"
user="{{.UserName}}"
cmd={{.Path}}
args="{{range .Arguments}} {{.|cmd}}{{end}}"
lockfile=/var/lock/subsys/$name
pidfile=/var/run/$name.pid

# Source networking configuration.
[ -r /etc/sysconfig/$name ] && . /etc/sysconfig/$name

start() {
    echo -n $"Starting $desc: "
    daemon \
        {{if .UserName}}--user=$user{{end}} \
        {{if .WorkingDirectory}}--chdir={{.WorkingDirectory|cmd}}{{end}} \
        "$cmd $args </dev/null >/dev/null 2>/dev/null & echo \$! > $pidfile"
    retval=$?
    [ $retval -eq 0 ] && touch $lockfile
    echo
    return $retval
}

stop() {
    echo -n $"Stopping $desc: "
    killproc -p $pidfile $cmd -TERM
    retval=$?
    [ $retval -eq 0 ] && rm -f $lockfile
    rm -f $pidfile
    echo
    return $retval
}

restart() {
    stop
    start
}

reload() {
    echo -n $"Reloading $desc: "
    killproc -p $pidfile $cmd -HUP
    RETVAL=$?
    echo
}

force_reload() {
    restart
}

rh_status() {
    status -p $pidfile $cmd
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}

case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    force-reload)
        force_reload
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart|reload|force-reload}"
        exit 2
esac
`

type NullService struct {
}

func (n *NullService) Start(s service.Service) error {
	return nil
}

func (n *NullService) Stop(s service.Service) error {
	return nil
}

func SysvScript() string {
	switch {
	case isDebianSysv():
		return sysvDebianScript
	case isRedhatSysv():
		return sysvRedhatScript
	}

	return ""
}

func isDebianSysv() bool {
	if _, err := os.Stat("/lib/lsb/init-functions"); err != nil {
		return false
	}
	if _, err := os.Stat("/sbin/start-stop-daemon"); err != nil {
		return false
	}
	return true
}

func isRedhatSysv() bool {
	if _, err := os.Stat("/etc/rc.d/init.d/functions"); err != nil {
		return false
	}
	return true
}

func getCurrentWorkingDirectory() string {
	dir, err := os.Getwd()
	if err == nil {
		return dir
	}
	return ""
}

func setupOSServiceConfig(c *cli.Context, config *service.Config) {
	switch runtime.GOOS {
	case osTypeWindows:
		config.Option = service.KeyValue{
			"Password": c.String("password"),
		}
		config.UserName = c.String("user")
	case osTypeLinux:
		if os.Getuid() != 0 {
			logrus.Fatal("The --user is not supported for non-root users")
		}

		user := c.String("user")
		if user != "" {
			config.Arguments = append(config.Arguments, "--user", user)
		}

		switch service.Platform() {
		case "linux-systemd":
			config.Dependencies = []string{
				"After=syslog.target network.target",
			}
			config.Option = service.KeyValue{
				"Restart": "always",
			}
		case "unix-systemv":
			script := SysvScript()
			if script != "" {
				config.Option = service.KeyValue{
					"SysvScript": script,
				}
			}
		}
	case osTypeDarwin:
		config.Option = service.KeyValue{
			"KeepAlive":   true,
			"RunAtLoad":   true,
			"UserService": os.Getuid() != 0,
		}

		user := c.String("user")
		if user == "" {
			return
		}

		if os.Getuid() != 0 {
			logrus.Fatal("The --user is not supported for non-root users")
		}

		config.Arguments = append(config.Arguments, "--user", user)
	default:
		logrus.Fatal("Operating system not supported")
	}
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
