// sec — a credentials broker for humans and their agents.
package main

import (
	"os"

	"github.com/muthuishere/secure-agent/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
