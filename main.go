package main

import (
	"log"
	"os"
	"sort"

	"agora-app/agora"
	"agora-app/commands"

	"github.com/urfave/cli/v2"
)

var appVersion = "3.0.0"

func main() {
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

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
