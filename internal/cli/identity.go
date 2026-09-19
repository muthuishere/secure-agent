package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("identity", "where the vault key lives; move it between the OS keyring and a file, or back it up", cmdIdentity)
}

func cmdIdentity(args []string) error {
	sub := "show"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "show":
		fs := flags("identity show")
		asJSON := fs.Bool("json", false, "machine output")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		s, err := open()
		if err != nil {
			return err
		}
		info := s.IdentityInfo()
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("backend    : %s\npublic key : %s\nlocation   : %s\n", info.Backend, info.PublicKey, info.Location)
		if info.Note != "" {
			fmt.Printf("note       : %s\n", info.Note)
		}
		if !store.KeyringAvailable() && info.Backend == store.BackendFile {
			fmt.Println("\n(no OS credential store on this machine — file is the right backend here)")
		}
		return nil

	case "move":
		fs := flags("identity move")
		to := fs.String("to", "", "keyring | file")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		if *to == "" {
			return fmt.Errorf("usage: sec identity move --to keyring|file")
		}
		if err := requireOwner("identity move"); err != nil {
			return err
		}
		s, err := open()
		if err != nil {
			return err
		}
		from := s.BackendName()
		if err := s.MoveIdentity(store.Backend(*to)); err != nil {
			return err
		}
		s.Audit("identity.move", owner.Agent(), nil, map[string]string{"from": string(from), "to": *to})
		info := s.IdentityInfo()
		fmt.Printf("✓ identity moved %s → %s\n  now at: %s\n", from, info.Backend, info.Location)
		if info.Note != "" {
			fmt.Printf("  ⚠ %s\n", info.Note)
		}
		return nil

	case "export":
		fs := flags("identity export")
		out := fs.String("out", "", "file to write the key to (0600)")
		confirm := fs.Bool("confirm", false, "required: this writes the key in plaintext")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		if *out == "" || !*confirm {
			return fmt.Errorf("usage: sec identity export --out FILE --confirm   (owner-only; put the file in a password manager, then delete it)")
		}
		if err := requireOwner("identity export"); err != nil {
			return err
		}
		s, err := open()
		if err != nil {
			return err
		}
		if err := s.ExportIdentity(*out); err != nil {
			return err
		}
		s.Audit("identity.export", owner.Agent(), nil, map[string]string{"out": *out})
		fmt.Printf("✓ identity written to %s (0600)\n  store it in a password manager, then delete the file.\n  Without it the vault cannot be decrypted by anyone, including you.\n", *out)
		return nil

	case "import":
		fs := flags("identity import")
		backend := fs.String("backend", "", "keyring | file (default: keyring if available)")
		rest, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(rest) != 1 {
			return fmt.Errorf("usage: sec identity import BACKUP_FILE [--backend keyring|file]")
		}
		if err := requireOwner("identity import"); err != nil {
			return err
		}
		s, err := open()
		if err != nil {
			// importing onto a fresh machine: init with the backup directly
			return fmt.Errorf("%w\n  on a fresh machine use: sec init --import-identity %s", err, rest[0])
		}
		b := store.Backend(*backend)
		if b == "" {
			b = store.DefaultBackend()
		}
		if err := s.ImportIdentity(rest[0], b); err != nil {
			return err
		}
		s.Audit("identity.import", owner.Agent(), nil, map[string]string{"backend": string(b)})
		fmt.Printf("✓ identity imported into %s\n", b)
		return nil
	}
	return fmt.Errorf("usage: sec identity [show|move --to keyring|file|export --out F --confirm|import FILE]")
}
