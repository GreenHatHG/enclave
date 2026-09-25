package command

import (
	"context"
	"fmt"
	"os"

	"github.com/kohkimakimoto/enclave/v3/internal/config"
	"github.com/kohkimakimoto/enclave/v3/internal/sandbox"
	"github.com/urfave/cli/v3"
)

func ProfileCommand() *cli.Command {
	return &cli.Command{
		Name:   "profile",
		Usage:  "Print evaluated profile and exit",
		Action: profileAction,
	}
}

func profileAction(ctx context.Context, cmd *cli.Command) error {
	// Inside sandbox: ENCLAVE_PROFILE points to the actual evaluated profile
	// file used by sandbox-exec at startup (including runtime-added entries
	// such as --allow-write / [sandbox] allow_write paths).
	if enclaveProfile := os.Getenv("ENCLAVE_PROFILE"); enclaveProfile != "" {
		content, err := os.ReadFile(enclaveProfile)
		if err != nil {
			return fmt.Errorf("failed to read profile %s: %w", enclaveProfile, err)
		}
		_, err = cmd.Root().Writer.Write(content)
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	wd, _ := os.Getwd()
	home, _ := os.UserHomeDir()

	profilePath, cleanup, err := sandbox.BuildProfile(cfg.SandboxProfile, cfg.SandboxAllowWrite, wd, home)
	if err != nil {
		return err
	}
	defer cleanup()

	content, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %w", err)
	}

	_, err = cmd.Root().Writer.Write(content)
	return err
}
