package agora

import (
	"agora-app/config"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/net/websocket"
)

const (
	osTypeLinux   = "linux"
	osTypeDarwin  = "darwin"
	osTypeWindows = "windows"
)

const (
	CommandHello            = "hello"
	CommandPing             = "ping"
	CommandDownload         = "download"
	CommandDownloadProgress = "download_progress"
	CommandRunTask          = "runTask"
)

type WsMessageData struct {
	Command string      `json:"command"`
	Data    interface{} `json:"data"`
}

type WsMessage struct {
	Stream   string        `json:"stream"`
	Receiver string        `json:"receiver"`
	Data     WsMessageData `json:"data"`
}

type VersionData struct {
	Major      int    `json:"major"`
	Minor      int    `json:"minor"`
	Path       int    `json:"path"`
	Snapshot   bool   `json:"snapshot"`
	VersionStr string `json:"string"`
}

type PingCommandData struct {
	AppId         string      `json:"appId"`
	BasePath      string      `json:"base_path"`
	ComputerName  string      `json:"computerName"`
	PathSeparator string      `json:"path_separator"`
	System        string      `json:"system"`
	Version       VersionData `json:"version"`
}

type PingData struct {
	Command string          `json:"command"`
	Data    PingCommandData `json:"data"`
}

type PingMessage struct {
	Stream string   `json:"stream"`
	Data   PingData `json:"data"`
}

type DownloadProgressCommandData struct {
	RequestId string  `json:"requestId"`
	Progress  float32 `json:"progress"`
}

type DownloadProgressData struct {
	Command string                      `json:"command"`
	Data    DownloadProgressCommandData `json:"data"`
}

type DownloadProgressMessage struct {
	Stream string               `json:"stream"`
	Data   DownloadProgressData `json:"data"`
}

func ParseVersion(version_str string) VersionData {
	version_str = strings.TrimSpace(version_str)
	version := VersionData{
		Major:      0,
		Minor:      0,
		Path:       1,
		Snapshot:   false,
		VersionStr: version_str,
	}
	if strings.Contains(strings.ToUpper(version_str), "SNAPSHOT") {
		version.Snapshot = true
	}
	version_str = strings.Split(version_str, "-")[0]
	version_str = strings.Split(version_str, " ")[0]
	version_splitted := strings.Split(version_str, ".")
	for index, element := range version_splitted {
		intVar, err := strconv.Atoi(element)
		if err == nil {
			if index == 0 {
				version.Major = intVar
			} else if index == 1 {
				version.Minor = intVar
			} else if index == 2 {
				version.Path = intVar
			}
		}

	}
	return version
}

func NewPingMessage(conf config.Configurations) PingMessage {
	hostname, _ := os.Hostname()

	system := "unknown"
	if runtime.GOOS == osTypeLinux || runtime.GOOS == osTypeDarwin {
		system = "unix"
	} else if runtime.GOOS == osTypeWindows {
		system = "windows"
	}

	version := AppVersion
	if version == "" {
		version = "0.0.1"
	}

	command_data := PingCommandData{
		AppId:         conf.General.Uid,
		BasePath:      filepath.ToSlash(conf.General.BasePath),
		ComputerName:  hostname,
		PathSeparator: string(os.PathSeparator),
		System:        system,
		Version:       ParseVersion(version),
	}

	data := PingData{
		Command: CommandPing,
		Data:    command_data,
	}

	msg := PingMessage{
		Stream: "App",
		Data:   data,
	}

	return msg
}

func NewDownloadProgressMessage(progress_pct float32, request_id string) DownloadProgressMessage {
	command_data := DownloadProgressCommandData{
		RequestId: request_id,
		Progress:  progress_pct,
	}

	data := DownloadProgressData{
		Command: CommandDownloadProgress,
		Data:    command_data,
	}

	msg := DownloadProgressMessage{
		Stream: "App",
		Data:   data,
	}

	return msg
}

func WsSendDownloadProgress(ws *websocket.Conn, progress_pct float32, request_id string) {
	websocket.JSON.Send(ws, NewDownloadProgressMessage(progress_pct, request_id))
}

func WsListen(ws *websocket.Conn) (data WsMessage, err error) {
	err = websocket.JSON.Receive(ws, &data)
	return data, err
}

func WsProcess(ws *websocket.Conn, data WsMessage, conf config.Configurations) {
	switch data.Data.Command {
	case CommandHello:
		websocket.JSON.Send(ws, NewPingMessage(conf))
	case CommandDownload:
		ProcessDownload(data, conf, ws)
	case CommandRunTask:
		ProcessRunTask(data, conf, ws)
	}
}

func Connect(conf config.Configurations) (ws *websocket.Conn, err error) {
	u, _ := url.Parse(conf.Agora.Url)
	var scheme = "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}
	u.Scheme = scheme
	request_url := u.String()

	config, err := websocket.NewConfig(request_url, request_url)
	if err != nil {
		return nil, err
	}
	config.Header = http.Header{
		"Authorization": {"Token " + conf.Agora.SessionKey},
	}

	if conf.General.NoCertificateCheck {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		config.TlsConfig = tlsConfig
	}

	ws, err = websocket.DialConfig(config)
	if err == nil {
		websocket.JSON.Send(ws, NewPingMessage(conf))
	}
	return ws, err
}

func StartWebSocket(conf config.Configurations) (ws *websocket.Conn, err error) {
	ws, err = Connect(conf)
	if err == nil {
		websocket.JSON.Send(ws, NewPingMessage(conf))
	}
	return ws, err
}
