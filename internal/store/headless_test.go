package store

import "testing"

func TestHeadlessDetection(t *testing.T) {
	// Clear anything the real environment sets, so each case is isolated.
	for _, v := range []string{"SEC_HEADLESS", "SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT", "CI", "GITHUB_ACTIONS", "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"} {
		t.Setenv(v, "")
	}
	cases := []struct {
		name     string
		env      map[string]string
		goos     string
		headless bool
	}{
		{"mac desktop", nil, "darwin", false},
		{"mac over ssh", map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, "darwin", true},
		{"mac in CI", map[string]string{"GITHUB_ACTIONS": "true"}, "darwin", true},
		{"linux server", nil, "linux", true},
		{"linux desktop", map[string]string{"DISPLAY": ":0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}, "linux", false},
		{"forced headless", map[string]string{"SEC_HEADLESS": "1"}, "darwin", true},
		{"forced not headless", map[string]string{"SEC_HEADLESS": "0", "SSH_CONNECTION": "x"}, "darwin", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			old := runtimeGOOS
			runtimeGOOS = tc.goos
			defer func() { runtimeGOOS = old }()
			got, why := Headless()
			if got != tc.headless {
				t.Fatalf("got headless=%v (%s), want %v", got, why, tc.headless)
			}
		})
	}
}

// A headless machine must never choose the keyring, on any platform.
func TestHeadlessForcesFileBackend(t *testing.T) {
	t.Setenv("SEC_HEADLESS", "1")
	if b := DefaultBackend(); b != BackendFile {
		t.Fatalf("headless default backend = %s, want file", b)
	}
	if KeyringAvailable() {
		t.Fatal("keyring must be reported unusable when headless")
	}
}
