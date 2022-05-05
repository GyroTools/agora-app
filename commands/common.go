package commands

import (
	"github.com/urfave/cli/v2"
)

var commands []*cli.Command
var flags []cli.Flag

type Commander interface {
	Execute(c *cli.Context)
}

func RegisterCommand(command *cli.Command) {
	commands = append(commands, command)
}

func AddFlags(new_flags []cli.Flag) {
	flags = append(flags, new_flags...)
}

func Get() []*cli.Command {
	return commands
}

func GetFlags() []cli.Flag {
	return flags
}
