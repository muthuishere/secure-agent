package cli

import (
	"fmt"
	"strings"

	"github.com/muthuishere/secure-agent/internal/envfile"
)

// envDepth bounds dotenv discovery. Four levels reaches
// infra/vault/<env>/.env.<env> without walking a whole monorepo.
const envDepth = 4

// resolveEnvSpec turns "TARGET" or "TARGET=VAR" into a concrete file.
//
// TARGET is either a path (used as given) or an environment name resolved
// against the dotenv files actually present. Defaulting to `.env` would write
// production credentials into whatever file happened to be in the way, so an
// environment that does not exist is an error, not a fallback.
func resolveEnvSpec(spec, defaultVar string) (path, variable, how string, err error) {
	target, v, hasVar := strings.Cut(spec, "=")
	if !hasVar {
		v = defaultVar
	}
	if v == "" && defaultVar == "" && hasVar {
		return "", "", "", fmt.Errorf("%s: empty variable name", spec)
	}
	path, how, err = envfile.ResolveTarget(".", target, envDepth)
	if err != nil {
		return "", "", "", err
	}
	return path, v, how, nil
}

// describeTarget is the one line printed when a bare environment name was
// resolved, so the file that was actually written is never a surprise.
func describeTarget(path, how string) string {
	if how == "path" {
		return path
	}
	return fmt.Sprintf("%s (%s)", path, how)
}
