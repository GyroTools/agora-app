package commands

import (
	"github.com/urfave/cli/v2"
)

var commands []*cli.Command

type Commander interface {
	Execute(c *cli.Context)
}

func RegisterCommand(command *cli.Command) {
	commands = append(commands, command)
}

func Get() []*cli.Command {
	return commands
}
