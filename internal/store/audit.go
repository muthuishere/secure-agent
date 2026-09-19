package store

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
)

type AuditEntry struct {
	TS     time.Time         `json:"ts"`
	Action string            `json:"action"`
	Names  []string          `json:"names,omitempty"`
	Agent  string            `json:"agent"`
	CWD    string            `json:"cwd,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Audit appends one line. Values never go here — only names and shape.
func (s *Store) Audit(action, agent string, names []string, fields map[string]string) {
	cwd, _ := os.Getwd()
	e := AuditEntry{TS: time.Now().UTC(), Action: action, Names: names, Agent: agent, CWD: cwd, Fields: fields}
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(s.AuditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// ReadAudit returns entries matching the filters (empty = all).
func (s *Store) ReadAudit(name, action string, since time.Time) ([]AuditEntry, error) {
	f, err := os.Open(s.AuditPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if !since.IsZero() && e.TS.Before(since) {
			continue
		}
		if action != "" && e.Action != action {
			continue
		}
		if name != "" && !contains(e.Names, name) {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// LastUsed maps secret name → most recent decrypt-for-use timestamp.
func (s *Store) LastUsed() map[string]time.Time {
	out := map[string]time.Time{}
	ents, _ := s.ReadAudit("", "", time.Time{})
	for _, e := range ents {
		if !strings.HasPrefix(e.Action, "exec") && e.Action != "run" && e.Action != "render" && e.Action != "get" {
			continue
		}
		for _, n := range e.Names {
			if e.TS.After(out[n]) {
				out[n] = e.TS
			}
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
