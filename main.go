package main

import (
	"fmt"
	"os"
	"sort"

	"agora-app/agora"
	"agora-app/commands"
	"agora-app/log"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var appVersion = "3.0.0"
var buildTime = "N.A."
var gitCommit = "N.A."
var gitRef = "N.A."

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("%s version %s\n", c.App.Name, c.App.Version)
		fmt.Printf("\nbuild time: %s\n", buildTime)
		fmt.Printf("git commit: %s\n", gitCommit)
		fmt.Printf("git ref: %s\n", gitRef)
	}

	commands.Init()

	agora.AppVersion = appVersion
	app := &cli.App{}
	app.Name = "agora-app"
	app.Usage = "for downloading files from Agora and executing local tasks"
	app.Version = appVersion
	app.Authors = []*cli.Author{
		{
			Name:  "Martin Buehrer",
			Email: "martin.buehrer@gyrotools.com",
		},
	}
	app.Commands = commands.Get()

	sort.Sort(cli.CommandsByName(app.Commands))

	log.ConfigureLogging(app)

	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}
