package sandbox

import (
	"os"
	"strings"
	"testing"
)

func TestBuildDefaultProfile_EmptyAllowWrite(t *testing.T) {
	if got := buildDefaultProfile(nil); got != DefaultProfile {
		t.Error("expected DefaultProfile unchanged when allowWrite is empty")
	}
	if got := buildDefaultProfile([]string{}); got != DefaultProfile {
		t.Error("expected DefaultProfile unchanged when allowWrite is empty slice")
	}
}

func TestBuildDefaultProfile_WithAllowWrite(t *testing.T) {
	got := buildDefaultProfile([]string{"/foo", "/bar"})

	for _, want := range []string{
		`(subpath (param "EXTRA_WRITE_0"))`,
		`(subpath (param "EXTRA_WRITE_1"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected profile to contain %q", want)
		}
	}

	// EXTRA_WRITE_0 must appear inside the allow file-write* block, i.e.
	// before the deny block.
	allowIdx := strings.Index(got, `(subpath (param "EXTRA_WRITE_0"))`)
	denyIdx := strings.Index(got, "Prevent modification of enclave config files")
	if allowIdx < 0 || denyIdx < 0 || allowIdx > denyIdx {
		t.Error("expected EXTRA_WRITE entries inside the allow file-write* block")
	}

	// count occurrences: exactly once each
	if c := strings.Count(got, "EXTRA_WRITE_0"); c != 1 {
		t.Errorf("expected exactly 1 occurrence of EXTRA_WRITE_0, got %d", c)
	}
}

func TestBuildProfile_CustomProfileAppendsAllowWrite(t *testing.T) {
	custom := "(version 1)\n(allow default)\n"
	path, cleanup, err := BuildProfile(custom, []string{"/foo"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.HasPrefix(got, custom) {
		t.Errorf("custom profile should be preserved, got %q", got)
	}
	if !strings.Contains(got, "(allow file-write*\n    (subpath (param \"EXTRA_WRITE_0\"))\n)") {
		t.Errorf("expected appended extra write block, got %q", got)
	}
}

func TestBuildProfile_DefaultWithAllowWrite(t *testing.T) {
	path, cleanup, err := BuildProfile("", []string{"/tmp/extra"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `(subpath (param "EXTRA_WRITE_0"))`) {
		t.Error("expected generated profile to contain EXTRA_WRITE_0")
	}
}
