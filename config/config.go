package config

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	uuid "github.com/nu7hatch/gouuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	osTypeLinux   = "linux"
	osTypeDarwin  = "darwin"
	osTypeWindows = "windows"
)

type Configurations struct {
	General GeneralConfigurations `yaml:"general"`
	Agora   AgoraConfigurations   `yaml:"agora"`
}

type AgoraConfigurations struct {
	Url        string `yaml:"url"`
	ApiKey     string `yaml:"api-key"`
	SessionKey string `yaml:"session-key"`
}

type GeneralConfigurations struct {
	Uid                 string `yaml:"uid"`
	BasePath            string `yaml:"base-path"`
	NrParallelDownloads int    `yaml:"nr-parallel-downloads"`
	NoCertificateCheck  bool   `yaml:"no-certificate-check"`
}

func NewConfig() Configurations {
	var c Configurations
	uuid, _ := uuid.NewV4()
	c.General.Uid = uuid.String()

	c.General.NrParallelDownloads = 3
	return c
}

func GetDefaultConfigFile() string {
	if (runtime.GOOS == osTypeLinux || runtime.GOOS == osTypeDarwin) && os.Getuid() == 0 {
		return "/etc/gyrotools/config.yml"
	}
	user_home, err := os.UserHomeDir()
	if err != nil {
		logrus.Fatal("Error cannot get the home directory: ", err)
	}
	filename := filepath.Join(user_home, ".gyrotools", "agora-app", "config.yml")
	return filename
}

func GetConf(config_file string, raise bool) (Configurations, error) {
	c := NewConfig()
	if _, err := os.Stat(config_file); errors.Is(err, os.ErrNotExist) {
		if raise {
			logrus.Fatal("No config file found. Please run \"agora-app register\" first")
		} else {
			WriteConf(c, config_file)
		}
	}

	yamlFile, err := ioutil.ReadFile(config_file)
	if err != nil {
		logrus.Error("Cannot read the config file: ", err)
		return c, err
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		logrus.Error("Cannot parse the config file:", err)
		return c, err
	}

	return c, nil
}

func WriteConf(c Configurations, config_file string) (err error) {
	parent := filepath.Dir(config_file)
	// create directories
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		err = os.MkdirAll(parent, os.ModePerm)
		if err != nil {
			logrus.Error("Error cannot create the directory: ", parent)
			return err
		}
	}

	file, err := os.OpenFile(config_file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logrus.Errorf("Error opening/creating the config file %s: ", config_file, err)
		return err
	}
	defer file.Close()

	enc := yaml.NewEncoder(file)

	err = enc.Encode(c)
	if err != nil {
		logrus.Error("Error encoding the config file: ", err)
		return err
	}

	return nil
}

func SetPermissions(config_file string) (err error) {
	// change file permissions
	if (runtime.GOOS == osTypeLinux || runtime.GOOS == osTypeDarwin) && os.Getuid() == 0 {
		err := os.Chmod(config_file, 0644)
		if err != nil {
			logrus.Error("Cannot change permissions for the config file: ", config_file)
		}
		return err
	}
	return nil
}
