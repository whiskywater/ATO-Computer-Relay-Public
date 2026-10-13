// ato-files supplies narrow filesystem parity operations through ATO command_run
// without adding a general-purpose shell or bypassing local filesystem policy.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/config"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/executor"
)

func main() {
	op := flag.String("op", "", "search, replace, copy, delete, page or hash")
	path := flag.String("path", "", "source path within allowed roots")
	to := flag.String("to", "", "copy target path within allowed roots")
	text := flag.String("text", "", "exact search string")
	replacement := flag.String("replacement", "", "replacement text")
	matches := flag.Int("matches", -1, "required expected match count for replace")
	offset := flag.Int64("offset", 0, "byte offset for page")
	limit := flag.Int("limit", 16384, "byte page size; at most 32768")
	configPath := flag.String("config", "", "existing production agent policy JSON")
	flag.Parse()
	if err := run(*op, *path, *to, *text, *replacement, *matches, *offset, *limit, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "ATO_FILES_ERROR:", err)
		os.Exit(1)
	}
}
func run(op, path, target, text, replacement string, matches int, offset int64, limit int, configPath string) error {
	if configPath == "" {
		return errors.New("agent config required")
	}
	cfg, err := config.LoadAgent(configPath)
	if err != nil {
		return err
	}
	p := cfg.Policy
	if path == "" {
		return errors.New("path required")
	}
	switch op {
	case "hash":
		checked, err := p.CheckPath(path, false)
		if err != nil {
			return err
		}
		f, err := os.Open(checked)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 512<<20 {
			return errors.New("hash requires regular file up to 512 MiB")
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		result := map[string]any{"path": checked, "size": info.Size(), "sha256": hex.EncodeToString(h.Sum(nil))}
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "page":
		if limit < 1 || limit > 32768 {
			return errors.New("page limit must be between 1 and 32768")
		}
		checked, err := p.CheckPath(path, false)
		if err != nil {
			return err
		}
		f, err := os.Open(checked)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("page path must be a regular file")
		}
		if offset < 0 || offset > info.Size() {
			return errors.New("page offset outside file")
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		buf, err := io.ReadAll(io.LimitReader(f, int64(limit)))
		if err != nil {
			return err
		}
		result := map[string]any{"path": checked, "offset": offset, "next_offset": offset + int64(len(buf)), "size": info.Size(), "has_more": offset+int64(len(buf)) < info.Size(), "content": string(buf)}
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "search", "replace":
		if text == "" {
			return errors.New("nonempty search text required")
		}
		p.AllowedTools = append(append([]string{}, p.AllowedTools...), "fs.search", "fs.replace")
		x := executor.New(p, "files-helper")
		defer x.Close()
		var method string
		var payload any
		if op == "search" {
			method = "fs.search"
			payload = map[string]any{"path": path, "text": text, "max_files": 500, "max_depth": 16, "max_bytes": 4 << 20, "max_matches": 100}
		} else {
			if matches < 0 {
				return errors.New("replace requires -matches expected-count")
			}
			method = "fs.replace"
			payload = map[string]any{"path": path, "search": text, "replace": replacement, "expected_matches": matches}
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		result, err := x.Handle(context.Background(), method, raw)
		if err != nil {
			return err
		}
		b, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if len(b) > 64<<10 {
			return errors.New("result exceeds 64 KiB helper output cap")
		}
		fmt.Println(string(b))
		return nil
	case "copy":
		if target == "" {
			return errors.New("copy target is required")
		}
		from, err := p.CheckPath(path, false)
		if err != nil {
			return err
		}
		to, err := p.CheckPath(target, true)
		if err != nil {
			return err
		}
		fi, err := os.Stat(from)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || fi.Size() > 64<<20 {
			return errors.New("source must be a regular file up to 64 MiB")
		}
		if filepath.Clean(from) == filepath.Clean(to) {
			return errors.New("copy cannot overwrite source")
		}
		input, err := os.Open(from)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, 64<<20+1))
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil || written > 64<<20 {
			_ = os.Remove(to)
			return errors.New("copy failed or exceeded limit")
		}
		fmt.Printf("{%q:%q,%q:%q,%q:%d}\n", "from", from, "to", to, "bytes_copied", written)
		return nil
	case "delete":
		checked, err := p.CheckPath(path, false)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(checked)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return errors.New("delete supports regular files only, not symlinks or directories")
		}
		// Deny removing the installed maintenance binaries and production session logs.
		if strings.EqualFold(filepath.Base(checked), "ato-maintainer.exe") || strings.EqualFold(filepath.Base(checked), "ato-files.exe") ||
			strings.Contains(strings.ToLower(checked), strings.ToLower("ATO-Run-Journal\\session-journals")) {
			return errors.New("refusing deletion of relay maintenance or active journal files")
		}
		if err := os.Remove(checked); err != nil {
			return err
		}
		fmt.Printf("{%q:%q,%q:true}\n", "path", checked, "deleted")
		return nil
	default:
		return errors.New("op must be search, replace, copy, delete, page or hash")
	}
}
