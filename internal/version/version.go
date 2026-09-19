// Package version holds build metadata stamped by the Taskfile / goreleaser.
package version

var (
	Version = "0.0.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string { return Version + " (" + Commit + ", " + Date + ")" }
