package sandbox

import (
	"fmt"
	"os"
	"strings"
)

// DefaultProfile is the built-in sandbox profile used when no custom profile is found.
const DefaultProfile = `(version 1)

(allow default)

(deny file-write*)
(allow file-write*
    ;; Working directory
    (subpath (param "WORKDIR"))

    ;; Claude Code
    (regex (string-append "^" (param "HOME") "/\\.claude"))

    ;; Keychain access for Claude Code credentials
    (subpath (string-append (param "HOME") "/Library/Keychains"))

    ;; Github Copilot
    (subpath (string-append (param "HOME") "/.copilot"))

	;; OpenCode
	(subpath (string-append (param "HOME") "/.opencode"))

    ;; Temporary directories and files
    (subpath "/tmp")
    (subpath "/var/folders")
    (subpath "/private/tmp")
    (subpath "/private/var/folders")

    ;; Home directory
    (subpath (string-append (param "HOME") "/.npm"))
    (subpath (string-append (param "HOME") "/.cache"))
    (subpath (string-append (param "HOME") "/Library/Caches"))
    (regex (string-append "^" (param "HOME") "/\\.viminfo"))

    ;; XDG directories
    (subpath (string-append (param "HOME") "/.config"))
    (subpath (string-append (param "HOME") "/.local/share"))
    (subpath (string-append (param "HOME") "/.local/state"))

    ;; devices
    (literal "/dev/stdout")
    (literal "/dev/stderr")
    (literal "/dev/null")
    (literal "/dev/dtracehelper")
    (regex #"^/dev/tty*")
)

;; Prevent modification of enclave config files to avoid sandbox escape via config changes
(deny file-write*
    (literal (string-append (param "HOME") "/.config/enclave/config.toml"))
    (regex (string-append "^" (param "WORKDIR") "/enclave\\.toml$"))
    (regex (string-append "^" (param "WORKDIR") "/enclave\\.local\\.toml$"))
)
`

// extraWriteMarker marks the position in DefaultProfile where extra
// writable path entries are inserted.
const extraWriteMarker = "    ;; devices\n"

// buildDefaultProfile returns the DefaultProfile with allowWrite paths
// inserted into the "allow file-write*" block as EXTRA_WRITE_N params.
// If allowWrite is empty, DefaultProfile is returned unchanged.
func buildDefaultProfile(allowWrite []string) string {
	if len(allowWrite) == 0 {
		return DefaultProfile
	}

	var b strings.Builder
	for i := range allowWrite {
		fmt.Fprintf(&b, "    (subpath (param %q))\n", fmt.Sprintf("EXTRA_WRITE_%d", i))
	}

	return strings.Replace(DefaultProfile, extraWriteMarker, b.String()+extraWriteMarker, 1)
}

// CommentedDefaultProfile returns the DefaultProfile with each line prefixed by "# ".
// Empty lines are commented as "#" (without trailing space).
func CommentedDefaultProfile() string {
	lines := strings.Split(strings.TrimRight(DefaultProfile, "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			lines[i] = "#"
		} else {
			lines[i] = "# " + line
		}
	}
	return strings.Join(lines, "\n")
}

// BuildProfile creates the sandbox profile file and returns its path and a
// cleanup function. The file is written to a deterministic path (sandbox.ProfilePath)
// so that sandboxed processes can find it via the ENCLAVE_PROFILE environment
// variable (see the `enclave profile` command).
// If profileContent is non-empty, it is used as the profile; allowWrite paths
// are appended at the end as a separate "allow file-write*" block (later rules
// take precedence in SBPL, so this overrides earlier deny rules).
// Otherwise, the built-in default profile is used.
// For each allowWrite path, a "(subpath (param "EXTRA_WRITE_N"))" line is
// generated; the caller must pass matching "-D EXTRA_WRITE_N=<path>"
// parameters to sandbox-exec.
func BuildProfile(profileContent string, allowWrite []string, wd, home string) (profilePath string, cleanup func(), err error) {
	content := profileContent
	if content == "" {
		content = buildDefaultProfile(allowWrite)
	} else if len(allowWrite) > 0 {
		var b strings.Builder
		b.WriteString(content)
		b.WriteString("\n;; Extra writable paths (from config [sandbox] allow_write / --allow-write)\n")
		b.WriteString("(allow file-write*\n")
		for i := range allowWrite {
			fmt.Fprintf(&b, "    (subpath (param %q))\n", fmt.Sprintf("EXTRA_WRITE_%d", i))
		}
		b.WriteString(")\n")
		content = b.String()
	}

	// Append a comment block mapping sandbox-exec params to their actual values,
	// so processes reading the profile file (e.g. via `enclave profile`) can see
	// the resolved paths instead of bare param placeholders.
	if params := paramValues(wd, home, allowWrite); len(params) > 0 {
		var b strings.Builder
		b.WriteString(content)
		b.WriteString("\n;; Resolved parameter values (passed to sandbox-exec via -D)\n")
		for k, v := range params {
			fmt.Fprintf(&b, ";;   %-14s = %s\n", k, v)
		}
		content = b.String()
	}

	// Write to the profile file (deterministic path so the sandboxed process
	// can inspect it via ENCLAVE_PROFILE)
	profilePath = ProfilePath()
	tmpFile, err := os.Create(profilePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create profile file %s: %w", profilePath, err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", nil, fmt.Errorf("failed to write profile: %w", err)
	}
	tmpFile.Close()

	cleanup = func() {
		os.Remove(tmpFile.Name())
	}

	return tmpFile.Name(), cleanup, nil
}

// paramValues returns the sandbox-exec -D parameter mapping for the given
// workdir, home and extra writable paths. Comments are emitted only when at
// least one extra write path is set (WORKDIR/HOME alone add little value).
func paramValues(wd, home string, allowWrite []string) map[string]string {
	if len(allowWrite) == 0 {
		return nil
	}
	params := map[string]string{
		"WORKDIR": wd,
		"HOME":    home,
	}
	for i, p := range allowWrite {
		params[fmt.Sprintf("EXTRA_WRITE_%d", i)] = p
	}
	return params
}
