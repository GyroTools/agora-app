package agora

import (
	"agora-app/config"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/websocket"
)

var AppVersion = "0.0.1"

type ApiKeyResponse struct {
	ApiKey string `json:"key"`
}

type CopyFile struct {
	SourcePath string
	TargetPath string
	Filename   string
}

type CopyData struct {
	Files     []CopyFile `json:"files"`
	RequestId string     `json:"requestId"`
}

type DownloadFile struct {
	ID         int
	TargetPath string
	Filename   string
	Size       int64
	Hash       string
}

type DownloadDataRaw struct {
	Files     []interface{} `json:"files"`
	RequestId string        `json:"requestId"`
}

type DownloadData struct {
	Files     []DownloadFile `json:"files"`
	RequestId string         `json:"requestId"`
}

type DownloadFileProgress struct {
	Path        string
	Size        int64
	Transferred int64
}

type DownloadProgress struct {
	NrFiles   int
	TotalSize int64
	Files     []DownloadFileProgress
}

type TaskTarget struct {
	ID   int
	Type string
}

type EnvValue struct {
	Value string `json:"value"`
	Add   bool   `json:"add"`
}

type EnvironmentVariable struct {
	Key   string
	Value string
	Add   bool
}

type TaskFile struct {
	ID         int
	TargetPath string
	Filename   string
	Size       int64
}

type AdditionalScript struct {
	Name       string `json:"name"`
	ScriptPath string `json:"scriptPath"`
	Script     string `json:"script"`
}

type TaskDataRaw struct {
	AdditionalScripts []AdditionalScript  `json:"additionalScripts"`
	CommandLine       string              `json:"commandLine"`
	Environment       map[string]EnvValue `json:"environment"`
	Name              string              `json:"name"`
	TaskDefinition    int                 `json:"taskDefinition"`
	TaskInfo          int                 `json:"taskInfo"`
	OutputDirectory   string              `json:"outputDirectory"`
	Script            string              `json:"script"`
	ScriptPath        string              `json:"scriptPath"`
	RequestID         string              `json:"requestId"`
	Files             []interface{}       `json:"files"`
	Target            []interface{}       `json:"target"`
}

type TaskData struct {
	AdditionalScripts []AdditionalScript
	CommandLine       string
	Environment       []EnvironmentVariable
	Name              string
	TaskDefinition    int
	TaskInfo          int
	OutputDirectory   string
	Script            string
	ScriptPath        string
	RequestID         string
	Files             []DownloadFile
	Target            TaskTarget
}

func join_url(agora_url string, path_str string) string {
	u, _ := url.Parse(agora_url)
	u.Path = path.Join(u.Path, path_str)
	request_url := u.String()
	return request_url
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func GetRequest(request_url string, api_key string, user string, password string) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", request_url, nil)
	if err != nil {
		return nil, err
	}

	if api_key != "" {
		req.Header.Set("Authorization", "X-Agora-Api-Key "+api_key)
	} else if user != "" && password != "" {
		req.Header.Add("Authorization", "Basic "+basicAuth(user, password))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func PostRequest(request_url string, body []byte, api_key string, user string, password string, content_type string) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", request_url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	if api_key != "" {
		req.Header.Set("Authorization", "X-Agora-Api-Key "+api_key)
	} else if user != "" && password != "" {
		req.Header.Add("Authorization", "Basic "+basicAuth(user, password))
	}
	if content_type != "" {
		req.Header.Set("Content-Type", content_type)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func Ping(agora_url string) bool {
	request_url := join_url(agora_url, "/api/v1/version/")
	resp, err := GetRequest(request_url, "", "", "")
	return err == nil && resp.StatusCode == 200
}

func CheckConnection(agora_url string, apikey string) bool {
	request_url := join_url(agora_url, "/api/v1/user/current/")
	resp, err := GetRequest(request_url, apikey, "", "")
	return err == nil && resp.StatusCode == 200
}

func Login(agora_url string, user string, password string) string {
	data := map[string]string{"username": user, "password": password}
	json_data, err := json.Marshal(data)
	if err != nil {
		logrus.Fatal(err)
	}

	request_url := join_url(agora_url, "/api/v1/rest-auth/login/") + "/"
	resp, err := http.Post(request_url, "application/json", bytes.NewBuffer(json_data))

	if err != nil {
		logrus.Fatal(err)
	}
	if resp.StatusCode != 200 {
		logrus.Fatal("Could not get the session-key. http status = ", resp.StatusCode)
	}

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)

	session_key := res["key"].(string)
	return session_key
}

func GetApiKey(agora_url string, user string, password string) string {
	success := Ping(agora_url)
	if !success {
		fmt.Fprintf(os.Stderr, "Error: Cannot connect to the Agora server\n")
		os.Exit(1)
	}
	request_url := join_url(agora_url, "/api/v1/apikey/") + "/"
	resp, err := GetRequest(request_url, "", user, password)

	if err != nil {
		logrus.Fatal(err)
	}
	if resp.StatusCode == 404 {
		logrus.Fatal("No api-key found. Please create an api-key in your Agora user profile")
	} else if resp.StatusCode > 299 {
		logrus.Fatal("Could not get the api-key. http status = ", resp.StatusCode)
	}

	target := new(ApiKeyResponse)
	json.NewDecoder(resp.Body).Decode(target)
	return target.ApiKey
}

func (n *DownloadFile) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.ID, &n.TargetPath, &n.Filename, &n.Size, &n.Hash}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if g, e := len(tmp), wantLen; g != e {
		return fmt.Errorf("wrong number of fields in Notification: %d != %d", g, e)
	}
	return nil
}

func (n *TaskFile) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.ID, &n.TargetPath, &n.Filename, &n.Size}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if g, e := len(tmp), wantLen; g != e {
		return fmt.Errorf("wrong number of fields in Notification: %d != %d", g, e)
	}
	return nil
}

func (n *TaskTarget) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.ID, &n.Type}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if g, e := len(tmp), wantLen; g != e {
		return fmt.Errorf("wrong number of fields in Notification: %d != %d", g, e)
	}
	return nil
}

func sendProgress(done chan bool, progress DownloadProgress, ws *websocket.Conn, request_id string) {
	var stop bool = false
	var last_value float32 = 0.0
	for {
		select {
		case <-done:
			stop = true
			WsSendDownloadProgress(ws, 100.0, request_id)
		default:
			var transferred_bytes int64
			transferred_bytes = 0
			for _, cur_file := range progress.Files {
				file, err := os.Open(cur_file.Path)
				if err != nil {
					file.Close()
					continue
				}

				fi, err := file.Stat()
				if err != nil {
					file.Close()
					continue
				}
				size := fi.Size()
				transferred_bytes += size
				file.Close()
			}
			var percent float32 = 0.0
			if progress.TotalSize > 0 {
				percent = float32(transferred_bytes) / float32(progress.TotalSize) * 100
			}
			if percent != last_value {
				WsSendDownloadProgress(ws, percent, request_id)
				fmt.Printf("%.0f", percent)
				fmt.Println("%")
			}
			last_value = percent
		}
		if stop {
			break
		}
		time.Sleep(2 * time.Second)
	}
}

func getFileHash(filename string) string {
	hasher := sha1.New()
	f, err := os.Open(filename)
	if err != nil {
		logrus.Error("cannot create file hash: ", err)
		return ""
	}
	defer f.Close()
	if _, err := io.Copy(hasher, f); err != nil {
		logrus.Error("cannot create file hash: ", err)
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func downloadFile(agora_url string, api_key string, file DownloadFile) error {
	url_path := fmt.Sprintf("/api/v1/datafile/%d/download/", file.ID)
	request_url := join_url(agora_url, url_path) + "/"

	resp, err := GetRequest(request_url, api_key, "", "")
	if err != nil {
		logrus.Errorf("Error failed to download file %d: ", file.ID, err)
		return err
	}

	defer resp.Body.Close()

	filename := filepath.Join(file.TargetPath, file.Filename)
	parent := filepath.Dir(filename)

	// create directories
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		err = os.MkdirAll(parent, os.ModePerm)
		if err != nil {
			logrus.Error("Error cannot create the directory: ", parent)
			return err
		}
	}

	out, err := os.Create(filename)
	if err != nil {
		logrus.Errorf("Error cannot create the file %s: ", filename, err)
		return err
	}
	logrus.Infof("Downloading datafile: id = %d, target = %s", file.ID, filename)
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		logrus.Error("Error cannot create the directory: ", parent)
		return err
	}

	logrus.Infof("Download finished:  id = %d", file.ID)
	return nil
}

func downloadWorker(fileChan chan DownloadFile, conf config.Configurations, wg *sync.WaitGroup) {
	// Decreasing internal counter for wait-group as soon as goroutine finishes
	defer wg.Done()

	for file := range fileChan {
		downloadFile(conf.Agora.Url, conf.Agora.ApiKey, file)
	}
}

func downloadFiles(data DownloadData, conf config.Configurations, ws *websocket.Conn) {
	var total_size int64
	total_size = 0
	file_progress := []DownloadFileProgress{}
	for _, file := range data.Files {
		total_size += file.Size
		file_progress = append(file_progress, DownloadFileProgress{Path: filepath.Join(file.TargetPath, file.Filename), Size: file.Size, Transferred: 0})
	}

	progress := DownloadProgress{
		NrFiles:   len(data.Files),
		TotalSize: total_size,
		Files:     file_progress,
	}

	parallel_downloads := conf.General.NrParallelDownloads

	fileCh := make(chan DownloadFile, len(data.Files))
	wg := new(sync.WaitGroup)

	progressCh := make(chan bool)
	go sendProgress(progressCh, progress, ws, data.RequestId)

	// Adding routines to workgroup and running then
	for i := 0; i < parallel_downloads; i++ {
		wg.Add(1)
		go downloadWorker(fileCh, conf, wg)
	}

	// Processing all links by spreading them to `free` goroutines
	for _, file := range data.Files {
		fileCh <- file
	}

	// Closing channel (waiting in goroutines won't continue any more)
	close(fileCh)

	// Waiting for all goroutines to finish (otherwise they die as main routine dies)
	wg.Wait()
	progressCh <- true
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func copyFiles(data CopyData, conf config.Configurations) {
	for _, file := range data.Files {
		src := filepath.Join(file.SourcePath, file.Filename)
		dst := filepath.Join(file.TargetPath, file.Filename)
		err := copyFile(src, dst)
		if err != nil {
			logrus.Errorf("Cannot copy file %s to %s", src, dst)
		}
	}
}

func findSameHash(files []DownloadFile, index int) []int {
	var duplicates []int
	hash := files[index].Hash
	for i := range files {
		if i == index {
			continue
		}
		if files[i].Hash == hash {
			duplicates = append(duplicates, i)
		}
	}
	return duplicates
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getDuplicates(data DownloadData) (dd DownloadData, cd CopyData) {
	dd.RequestId = data.RequestId
	cd.RequestId = data.RequestId
	var duplicates []int
	for i := range data.Files {
		if contains(duplicates, i) {
			continue
		}
		dd.Files = append(dd.Files, data.Files[i])
		indices := findSameHash(data.Files, i)
		if len(indices) > 0 {
			duplicates = append(duplicates, indices...)
			for _, index := range indices {
				cd.Files = append(cd.Files, CopyFile{SourcePath: data.Files[i].TargetPath, TargetPath: data.Files[index].TargetPath, Filename: data.Files[index].Filename})
			}
		}
	}

	return dd, cd
}

func skipFiles(data DownloadData) (dd DownloadData) {
	dd.RequestId = data.RequestId
	for _, file := range data.Files {
		filename := filepath.Join(file.TargetPath, file.Filename)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			hash := getFileHash(filename)
			if hash == file.Hash {
				continue
			} else {
				e := os.Remove(filename)
				if e != nil {
					logrus.Error("Error cannot delete the file: ", filename)
				}
			}
		}
		dd.Files = append(dd.Files, file)
	}
	return dd
}

func saveScript(scriptPath string, script string) error {
	parent := filepath.Dir(scriptPath)
	err := os.MkdirAll(parent, os.ModePerm)
	if err != nil {
		logrus.Error("Error cannot create task output directory: ", parent)
		return err
	}
	decodedScript, _ := base64.StdEncoding.DecodeString(script)

	file, err := os.OpenFile(scriptPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logrus.Errorf("Error opening/creating the script file %s: ", scriptPath, err)
		return err
	}
	defer file.Close()

	file.Write(decodedScript)

	return nil
}

func performTask(cmdStr string, env []EnvironmentVariable) ([]byte, []byte, error) {
	args := strings.Fields(cmdStr)
	cmd := exec.Command(args[0], args[1:]...)

	if runtime.GOOS == osTypeWindows {
		args = append([]string{"/C"}, args...)
		cmd = exec.Command("cmd", args[0:]...)
	}

	if len(env) > 0 {
		cmd.Env = os.Environ()
		for _, e := range env {
			if e.Add {
				found := false
				for i, ee := range cmd.Env {
					pair := strings.SplitN(ee, "=", 2)
					existing_key := pair[0]
					new_key := e.Key
					if runtime.GOOS == osTypeWindows {
						existing_key = strings.ToLower(existing_key)
						new_key = strings.ToLower(new_key)
					}
					if existing_key == new_key {
						cmd.Env[i] = fmt.Sprintf("%s=%s%s", pair[0], pair[1], e.Value)
						found = true
						break
					}
				}
				if !found {
					cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", e.Key, e.Value[1:]))
				}
			} else {
				v := fmt.Sprintf("%s=%s", e.Key, e.Value)
				cmd.Env = append(cmd.Env, v)
			}
		}

	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func updateOutput(taskId int, output []byte, name string, agora_url string, api_key string) error {
	url_path := fmt.Sprintf("/api/v2/timeline/%d/%s_update/", taskId, name)

	request_url := join_url(agora_url, url_path) + "/"
	resp, err := PostRequest(request_url, output, api_key, "", "", "text/plain")
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("http status = %d", resp.StatusCode)
		return err
	}

	return nil
}

func dirIsEmpty(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1) // Or f.Readdir(1)
	if err == io.EOF {
		return true
	}
	return false // Either not empty or error, suits both cases
}

func runTask(data TaskData, conf config.Configurations, ws *websocket.Conn) error {
	if len(data.Files) > 0 {
		download_data := DownloadData{
			Files:     data.Files,
			RequestId: data.RequestID,
		}
		downloadFiles(download_data, conf, ws)
	}

	if data.OutputDirectory != "" {
		err := os.MkdirAll(data.OutputDirectory, os.ModePerm)
		if err != nil {
			logrus.Error("Error cannot create task output directory: ", data.OutputDirectory)
			return err
		}
	}

	if data.Script != "" && data.ScriptPath != "" {
		if err := saveScript(data.ScriptPath, data.Script); err != nil {
			logrus.Error("Cannot save the script: ", err)
			return err
		}
	}

	for _, additionalFile := range data.AdditionalScripts {
		scriptPath := additionalFile.ScriptPath
		script := additionalFile.Script
		if err := saveScript(scriptPath, script); err != nil {
			logrus.Error("Cannot save the script: ", err)
			return err
		}
	}

	stdout, stderr, err_task := performTask(data.CommandLine, data.Environment)
	if err_task != nil {
		logrus.Error("Error cannot perform the task: ", err_task)
	}

	err_stderr := updateOutput(data.TaskInfo, stderr, "stderr", conf.Agora.Url, conf.Agora.ApiKey)
	if err_stderr != nil {
		logrus.Error("Error could not update stderr: ", err_stderr)
	}
	err_stdout := updateOutput(data.TaskInfo, stdout, "stdout", conf.Agora.Url, conf.Agora.ApiKey)
	if err_stdout != nil {
		logrus.Error("Error could not update stdout: ", err_stdout)
	}

	if err_task == nil && !dirIsEmpty(data.OutputDirectory) {
		_, err := UploadTaskResults(conf.Agora.Url, conf.Agora.ApiKey, data.OutputDirectory, data.TaskDefinition, data.Target, true, -1)
		if err != nil {
			logrus.Error("Error could not upload results: ", err)
			return err
		}
	}

	return nil
}

func ProcessDownload(data WsMessage, conf config.Configurations, ws *websocket.Conn) {
	download_data_map := data.Data.Data
	var download_data_raw DownloadDataRaw
	mapstructure.Decode(download_data_map, &download_data_raw)
	download_files_json, err := json.Marshal(download_data_raw.Files)
	if err != nil {
		logrus.Error("error:", err)
	}
	var download_files []DownloadFile
	if err := json.Unmarshal([]byte(download_files_json), &download_files); err != nil {
		logrus.Error("Cannot parse download file: ", err)
	}

	download_data := DownloadData{
		Files:     download_files,
		RequestId: download_data_raw.RequestId,
	}

	// do not re-download files if they already exist and the hash is the same
	download_data = skipFiles(download_data)
	// do not re-download identical files. Just download one and then copy it to the target destination(s)
	download_data, copy_data := getDuplicates(download_data)

	downloadFiles(download_data, conf, ws)
	copyFiles(copy_data, conf)
}

func ProcessRunTask(data WsMessage, conf config.Configurations, ws *websocket.Conn) {
	task_data_map := data.Data.Data
	var task_data_raw TaskDataRaw
	mapstructure.Decode(task_data_map, &task_data_raw)
	target_json, err := json.Marshal(task_data_raw.Target)
	if err != nil {
		logrus.Error("error:", err)
	}
	files_json, err := json.Marshal(task_data_raw.Files)
	if err != nil {
		logrus.Error("error:", err)
	}
	var target TaskTarget
	if err := json.Unmarshal([]byte(target_json), &target); err != nil {
		logrus.Error("Cannot parse task run data: ", err)
	}
	var files []TaskFile
	if err := json.Unmarshal([]byte(files_json), &files); err != nil {
		logrus.Error("Cannot parse task run data: ", err)
	}

	var download_files []DownloadFile
	for _, file := range files {
		download_files = append(download_files, DownloadFile{
			ID:         file.ID,
			TargetPath: file.TargetPath,
			Filename:   file.Filename,
			Size:       file.Size,
			Hash:       "",
		})
	}

	var env []EnvironmentVariable
	for k, v := range task_data_raw.Environment {
		env = append(env, EnvironmentVariable{Key: k, Value: v.Value, Add: v.Add})
	}

	task_data := TaskData{
		AdditionalScripts: task_data_raw.AdditionalScripts,
		CommandLine:       task_data_raw.CommandLine,
		Environment:       env,
		Name:              task_data_raw.Name,
		TaskDefinition:    task_data_raw.TaskDefinition,
		TaskInfo:          task_data_raw.TaskInfo,
		OutputDirectory:   task_data_raw.OutputDirectory,
		Script:            task_data_raw.Script,
		ScriptPath:        task_data_raw.ScriptPath,
		RequestID:         task_data_raw.RequestID,
		Files:             download_files,
		Target:            target,
	}

	runTask(task_data, conf, ws)
}
