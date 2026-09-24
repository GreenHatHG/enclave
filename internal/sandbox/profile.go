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

// BuildProfile creates a temporary file with the sandbox profile and returns
// its path and a cleanup function.
// If profileContent is non-empty, it is used as the profile.
// Otherwise, the built-in default profile is used.
// allowWrite paths are applied only with the default profile: for each path,
// a "(subpath (param "EXTRA_WRITE_N"))" line is inserted into the
// "allow file-write*" block; the caller must pass matching "-D EXTRA_WRITE_N=<path>"
// parameters to sandbox-exec.
func BuildProfile(profileContent string, allowWrite []string) (profilePath string, cleanup func(), err error) {
	content := profileContent
	if content == "" {
		content = buildDefaultProfile(allowWrite)
	}

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "enclave-profile-*.sb")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
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
