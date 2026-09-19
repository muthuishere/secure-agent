package store

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// Headless reports whether this process is running without an interactive
// desktop session, and why.
//
// It matters because every OS credential store assumes a logged-in desktop:
// macOS locks the login keychain in an SSH session and `security` will prompt
// on the terminal, Linux's Secret Service needs a running gnome-keyring and
// blocks in Unlock, and a container has neither. A prompt nobody can answer is
// a hung agent, a stuck cron job, or a CI build that times out — so when there
// is no session, the identity belongs in a file (or SEC_IDENTITY).
func Headless() (bool, string) {
	// An explicit answer always wins — someone running a GUI agent under
	// launchd, or forcing the file backend on a desktop.
	switch os.Getenv("SEC_HEADLESS") {
	case "1", "true":
		return true, "SEC_HEADLESS is set"
	case "0", "false":
		return false, ""
	}
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != "" {
		return true, "SSH session"
	}
	if inContainer() {
		return true, "container"
	}
	if isCI() {
		return true, "CI"
	}
	switch runtimeGOOS {
	case "darwin", "windows":
		// A desktop session is the normal case; SSH and containers are caught above.
		return false, ""
	default:
		// X11/Wayland/DBus are what a Secret Service needs to exist at all.
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return true, "no DISPLAY/WAYLAND_DISPLAY"
		}
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			return true, "no DBUS_SESSION_BUS_ADDRESS"
		}
		return false, ""
	}
}

func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, marker := range []string{"docker", "containerd", "kubepods", "lxc"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}

func isCI() bool {
	for _, v := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "CIRCLECI"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// probeTimeout bounds the availability check. Nothing here should take more
// than a few milliseconds; anything longer is a prompt waiting for a human.
const probeTimeout = 3 * time.Second

// keyringGet reads one item, bounded by the same timeout as the probe: a
// locked keychain in an SSH session will otherwise prompt on the terminal
// and hang whatever agent or cron job is driving us.
func keyringGet(account string) (string, error) {
	type res struct {
		v   string
		err error
	}
	done := make(chan res, 1)
	go func() {
		v, err := keyring.Get(keyringService, account)
		done <- res{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-time.After(probeTimeout):
		return "", fmt.Errorf("credential store did not answer in %s (locked, or waiting on a prompt)", probeTimeout)
	}
}

// probeKeyring does a real write/read/delete round trip, bounded by a timeout
// so a credential store that decides to ask a question can never wedge us.
//
// A timed-out probe leaks a goroutine blocked in the keyring call for as long
// as the prompt stands. That is deliberate: the alternative is killing a
// process mid-write to the user's keychain.
func probeKeyring() error {
	const probe = "sec-probe"
	done := make(chan error, 1)
	go func() {
		if err := keyring.Set(keyringService, probe, "probe"); err != nil {
			done <- err
			return
		}
		v, err := keyring.Get(keyringService, probe)
		keyring.Delete(keyringService, probe)
		if err != nil {
			done <- err
			return
		}
		if v != "probe" {
			done <- fmt.Errorf("keyring returned a different value than it stored")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(probeTimeout):
		return fmt.Errorf("credential store did not answer in %s (locked, or waiting on a prompt)", probeTimeout)
	}
}
