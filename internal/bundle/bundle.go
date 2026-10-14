// Package bundle turns a file or a folder into one byte blob the vault can
// encrypt, and writes it back out atomically. A folder becomes a gzipped tar
// of regular files and directories with their permission bits; symlinks and
// devices are skipped so a bundle can never point outside its target.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	KindValue = ""     // a plain value (the default)
	KindFile  = "file" // one file's bytes
	KindDir   = "dir"  // a folder, as tar.gz
)

// Read loads path as a bundle and reports its kind. skipped lists entries
// that were left out (symlinks, sockets, …).
func Read(path string) (data []byte, kind string, skipped []string, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", nil, err
	}
	if !st.IsDir() {
		b, err := os.ReadFile(path)
		return b, KindFile, nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(path, p)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			skipped = append(skipped, rel)
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uname, hdr.Gname, hdr.Uid, hdr.Gid = "", "", 0, 0
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = gz.Close()
	}
	return buf.Bytes(), KindDir, skipped, err
}

// Write puts a bundle at path atomically: a file via temp+rename, a folder
// by extracting beside it and swapping it in. mode applies to a file (0 keeps
// 0600); a folder keeps the modes it was stored with.
func Write(path, kind string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if kind != KindDir {
		if mode == 0 {
			mode = 0o600
		}
		tmp := path + ".sec-tmp"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	tmp, old := path+".sec-tmp", path+".sec-old"
	os.RemoveAll(tmp)
	if err := extract(data, tmp); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	os.RemoveAll(old)
	if _, err := os.Lstat(path); err == nil {
		if err := os.Rename(path, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Rename(old, path)
		return err
	}
	return os.RemoveAll(old)
}

func extract(data []byte, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not a folder bundle: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("bundle entry escapes target: %s", hdr.Name)
		}
		dst := filepath.Join(dir, name)
		mode := os.FileMode(hdr.Mode).Perm()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
}

// Files lists the entries of a folder bundle (for display, never contents).
func Files(data []byte) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, hdr.Name)
	}
}
