// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/command/exec"
)

// PreprocessSource runs clang -E on the given BPF source file. nodeConfig and
// epConfig are called to write the respective header files into a temporary
// directory. The preprocessed output is streamed to out.
//
// sourceFile is a filename relative to bpfDir (e.g. "bpf_lxc.c"). bpfDir is
// the path to the bpf/ source tree.
func PreprocessSource(
	ctx context.Context,
	nodeConfig func(io.Writer) error,
	epConfig func(io.Writer) error,
	sourceFile, bpfDir string,
	out io.Writer,
) error {
	tmpDir, err := os.MkdirTemp("", "cilium-preprocess-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	globalsDir := filepath.Join(tmpDir, "globals")
	if err := os.Mkdir(globalsDir, 0o700); err != nil {
		return fmt.Errorf("creating globals dir: %w", err)
	}

	if err := writeHeader(filepath.Join(globalsDir, "node_config.h"), nodeConfig); err != nil {
		return fmt.Errorf("writing node_config.h: %w", err)
	}
	if err := writeHeader(filepath.Join(tmpDir, "ep_config.h"), epConfig); err != nil {
		return fmt.Errorf("writing ep_config.h: %w", err)
	}

	return runPreprocess(ctx, sourceFile, bpfDir, tmpDir, out)
}

func writeHeader(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

// runPreprocess invokes clang -E with the include paths assembled from
// stateDir (globals/, ep_config.h) and bpfDir (BPF source tree).
//
// -mcpu and __NR_CPUS__ are set to safe stub values: the C preprocessor does
// not generate code, so CPU ISA detection (which requires CAP_BPF) is
// unnecessary.
func runPreprocess(ctx context.Context, sourceFile, bpfDir, stateDir string, out io.Writer) error {
	args := []string{
		fmt.Sprintf("-I%s", path.Join(stateDir, "globals")),
		fmt.Sprintf("-I%s", stateDir),
		fmt.Sprintf("-I%s", bpfDir),
		fmt.Sprintf("-I%s", path.Join(bpfDir, "include")),
		"-E",
	}
	args = append(args, standardCFlags...)
	args = append(args, "-D__NR_CPUS__=1")
	args = append(args, "-mcpu=v1")
	args = append(args,
		"-c", path.Join(bpfDir, sourceFile),
		"-o", "-",
	)

	log.WithFields(logrus.Fields{
		"target": compiler,
		"args":   args,
	}).Debug("Running BPF preprocessor")

	cmd, cancel := exec.WithCancel(ctx, compiler, args...)
	defer cancel()

	cmd.Stdout = out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) &&
			cmd.ProcessState != nil &&
			!cmd.ProcessState.Exited() &&
			strings.HasSuffix(err.Error(), syscall.SIGKILL.String()) {
			err = errors.Join(err, ctx.Err())
		}
		scanner := bufio.NewScanner(io.LimitReader(&stderr, 1_000_000))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return fmt.Errorf("preprocessing %s: %w", sourceFile, err)
	}

	return nil
}
