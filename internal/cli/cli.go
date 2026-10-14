// Package cli wires subcommands. Stdlib flag only, one file per verb group.
package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/store"
	"github.com/muthuishere/secure-agent/internal/version"
)

type command struct {
	name, summary string
	run           func(args []string) error
}

var commands []command

func register(name, summary string, run func([]string) error) {
	commands = append(commands, command{name, summary, run})
}

// Main dispatches. Exit codes: 0 ok, 1 error, 2 usage, child code for exec/run.
func Main(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		return 0
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		fmt.Println("sec", version.String())
		return 0
	}
	for _, c := range commands {
		if c.name == args[0] {
			err := c.run(args[1:])
			var ec exitCode
			if errors.As(err, &ec) {
				return int(ec)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "sec:", err)
				return 1
			}
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "sec: unknown command %q\n\n", args[0])
	usage()
	return 2
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func usage() {
	fmt.Println(`sec — credentials broker for humans and their agents.
Agents write {{NAME}} placeholders; sec fills them, runs the work, scrubs the output.

Usage: sec <command> [flags]

Commands:`)
	sort.Slice(commands, func(i, j int) bool { return commands[i].name < commands[j].name })
	for _, c := range commands {
		fmt.Printf("  %-12s %s\n", c.name, c.summary)
	}
	fmt.Println(`
Owner-only flags (--print, --confirm, export) need a TTY on stdin or SEC_OWNER=1.
Home: ` + store.Home() + `  (override with SEC_HOME)`)
}

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("sec "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parse runs fs on args and returns the rest; flag errors become usage exits.
// Go's flag stops at the first positional, so `sec set NAME --tag x` would
// silently ignore --tag. Leading positionals are moved after the flags;
// anything after a literal -- is left untouched, in order.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var lead []string
	i := 0
	for i < len(args) && !strings.HasPrefix(args[i], "-") {
		lead = append(lead, args[i])
		i++
	}
	if err := fs.Parse(args[i:]); err != nil {
		return nil, exitCode(2)
	}
	return append(lead, fs.Args()...), nil
}

func open() (*store.Store, error) { return store.Open() }

func requireOwner(what string) error {
	if !owner.IsOwner() {
		return fmt.Errorf("%s is owner-only: it would expose a value. Ask the owner to run it (they may add SEC_OWNER=1)", what)
	}
	return nil
}

// readSecret gets a value without it touching argv: masked prompt on a TTY
// ('*' per key, last 3 chars shown after a paste),
// otherwise raw stdin (heredoc / pipe). Trailing newline is stripped unless
// --raw keeps it (multi-line material like PEM/JSON).
func readSecret(prompt string, raw bool) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := readMasked(int(os.Stdin.Fd()), os.Stdin, os.Stderr, prompt+" (input masked): ")
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, errors.New("empty value")
		}
		return b, nil
	}
	b, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return nil, err
	}
	if !raw {
		b = []byte(strings.TrimRight(string(b), "\r\n"))
	}
	if len(b) == 0 {
		return nil, errors.New("empty value on stdin")
	}
	return b, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
