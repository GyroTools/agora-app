package commands

import (
	"agora-app/agora"
	"agora-app/config"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func Upload(c *cli.Context) error {
	conf, err := config.GetConf(config.GetDefaultConfigFile(), false)
	if err != nil {
		logrus.Fatal("Cannot read the config file")
	}
	_, err = agora.Upload(conf.Agora.Url, conf.Agora.ApiKey, c.String("path"), c.Int("target-folder"), c.Bool("extract-zip"), c.String("import-json"), true, -1, c.Bool("fake"))
	if err != nil {
		logrus.Fatal(err)
	}
	return nil
}

func init() {
	RegisterCommand(&cli.Command{
		Name:  "upload",
		Usage: "upload files",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Aliases:  []string{"p"},
				Value:    "",
				Usage:    "The path to a file or folder to be uploaded",
				Required: true,
			},
			&cli.IntFlag{
				Name:     "target-folder",
				Aliases:  []string{"f"},
				Value:    -1,
				Usage:    "The ID of the target folder where the data is uploaded to",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "extract-zip",
				Usage: "If the uploaded file is a zip, it is extracted and its content is imported into Agora",
			},
			&cli.StringFlag{
				Name:    "import-json",
				Aliases: []string{"j"},
				Value:   "",
				Usage:   "The json which will be used for the import",
			},
			&cli.BoolFlag{
				Name:  "fake",
				Usage: "Run the uploader without actually uploading the files (for testing and debugging)",
			},
		},
		Action: Upload,
	})
}
