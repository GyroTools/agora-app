package commands

import (
	"agora-app/agora"
	"agora-app/config"
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

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
	c, err := config.GetConf(config_file)
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
			conf := run(c.String("download-path"), c.String("url"), c.String("user"), c.String("password"), c.String("config"))
			config.WriteConf(conf, c.String("config"))
			os.Exit(0)
			return nil
		},
	}

	RegisterCommand(&command)
}
