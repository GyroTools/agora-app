package commands

import (
	"agora-app/agora"
	"agora-app/config"
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func userModeWarning(withRun bool) {
	logrus.WithFields(logrus.Fields{
		"GOOS": runtime.GOOS,
		"uid":  os.Getuid(),
	}).Debugln("Checking runtime mode")

	// everything is supported on windows
	if runtime.GOOS == osTypeWindows {
		return
	}

	systemMode := os.Getuid() == 0

	// We support services on Linux, Windows and Darwin
	noServices :=
		runtime.GOOS != osTypeLinux &&
			runtime.GOOS != osTypeDarwin

	// We don't support services installed as an User on Linux
	noUserService :=
		!systemMode &&
			runtime.GOOS == osTypeLinux

	if systemMode {
		logrus.Infoln("Running in system-mode.")
	} else {
		logrus.Warningln("Running in user-mode.")
	}

	if withRun {
		if noServices {
			logrus.Warningln("You need to manually start builds processing:")
			logrus.Warningln("$ gitlab-runner run")
		} else if noUserService {
			logrus.Warningln("The user-mode requires you to manually start builds processing:")
			logrus.Warningln("$ gitlab-runner run")
		}
	}

	if !systemMode {
		logrus.Warningln("Use sudo for system-mode:")
		logrus.Warningln("$ sudo gitlab-runner...")
	}
	logrus.Infoln("")
}

func isUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && str != "" && u.Scheme != "" && u.Host != ""
}

func user_input(question string, default_value string, example string) string {
	reader := bufio.NewReader(os.Stdin)

	default_display := ""
	example_display := ""
	if default_value != "" {
		default_display = fmt.Sprintf(" [%s]", default_value)
	} else if example != "" {
		example_display = fmt.Sprintf(" (e.g. %s)", example)
	}

	fmt.Printf("%s%s%s: ", question, example_display, default_display)
	answer, err := reader.ReadString('\n')
	if err != nil || answer == "\r\n" || answer == "\r" || answer == "\n" {
		return default_value
	}
	return strings.TrimSpace(answer)
}

func credentials() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Agora Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	fmt.Print("Agora Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}

func run(download_path string, agora_url string, user string, password string, config_file string) config.Configurations {
	c, err := config.GetConf(config_file, false)
	if err != nil {
		logrus.Fatal("Cannot read the config file")
	}

	if len(download_path) > 0 {
		c.General.BasePath = download_path
	} else {
		default_download_path := ""
		if c.General.BasePath != "" {
			default_download_path = c.General.BasePath
		}
		c.General.BasePath = user_input("Enter the download path for the data", default_download_path, "")
		if _, err := os.Stat(c.General.BasePath); errors.Is(err, os.ErrNotExist) {
			logrus.Fatal("The path is invalid or does not exist")
		}
	}

	if len(agora_url) > 0 {
		c.Agora.Url = agora_url
	} else {
		default_url := ""
		if c.Agora.Url != "" {
			default_url = c.Agora.Url
		}
		c.Agora.Url = user_input("Enter the Agora URL", default_url, "https://my_agora.com")
		if !isUrl(c.Agora.Url) {
			logrus.Fatal("Please enter a valid Agora url")
		}
	}

	if len(user) == 0 || len(password) == 0 {
		user1, password1, _ := credentials()
		if len(user) == 0 {
			user = user1
		}
		if len(password) == 0 {
			password = password1
		}
	}
	fmt.Print("\nPlease wait...")

	api_key := agora.GetApiKey(c.Agora.Url, user, password)
	success := agora.CheckConnection(c.Agora.Url, api_key)
	if !success {
		fmt.Fprintf(os.Stderr, "Error: Cannot connect to the Agora server with the api-key\n")
		os.Exit(1)
	}
	c.Agora.ApiKey = api_key

	session_key := agora.Login(c.Agora.Url, user, password)
	c.Agora.SessionKey = session_key

	fmt.Println(" done")
	return c
}

func init() {
	command := cli.Command{
		Name:  "register",
		Usage: "register app",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "download-path",
				Value: "",
				Usage: "The base path where the agora-app stores the downloaded files",
			},
			&cli.StringFlag{
				Name:  "url",
				Value: "",
				Usage: "The url of the Agora server (for example https://my_agora.com)",
			},
			&cli.StringFlag{
				Name:  "user",
				Value: "",
				Usage: "The Agora username",
			},
			&cli.StringFlag{
				Name:  "password",
				Value: "",
				Usage: "The Agora password",
			},
			&cli.StringFlag{
				Name:  "config",
				Value: config.GetDefaultConfigFile(),
				Usage: "The path to the config file",
			},
		},
		Action: func(c *cli.Context) error {
			userModeWarning(true)
			conf := run(c.String("download-path"), c.String("url"), c.String("user"), c.String("password"), c.String("config"))
			config.WriteConf(conf, c.String("config"))
			config.SetPermissions(c.String("config"))
			fmt.Println("Config file written to: ", c.String("config"))
			os.Exit(0)
			return nil
		},
	}

	RegisterCommand(&command)
}
