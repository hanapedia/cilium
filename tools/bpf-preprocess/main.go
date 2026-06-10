// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// bpf-preprocess resolves #ifdef blocks in a Cilium BPF source file according
// to the feature flags in a supplied Cilium ConfigMap. It uses unifdef(1) to
// remove dead branches while preserving #include directives and all other code
// unchanged, producing a plain C file that is much easier to read.
//
// Usage:
//
//	bpf-preprocess --config cilium-config.yaml --program bpf_lxc.c [--bpf-dir ./bpf]
//
// The --config flag accepts either a full Kubernetes ConfigMap YAML (with
// apiVersion/kind/metadata/data fields) or a bare key-value YAML map.
//
// To obtain the config from a running cluster:
//
//	kubectl get cm -n kube-system cilium-config -o yaml > cilium-config.yaml
//
// unifdef(1) must be installed and on PATH. On Debian/Ubuntu: apt install unifdef
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/option"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var (
	flagConfig  string
	flagProgram string
	flagBPFDir  string
)

var rootCmd = &cobra.Command{
	Use:   "bpf-preprocess",
	Short: "Resolve #ifdef blocks in a Cilium BPF source file using a given Cilium ConfigMap",
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVar(&flagConfig, "config", "", "Path to Cilium ConfigMap YAML file (required)")
	rootCmd.Flags().StringVar(&flagProgram, "program", "", "BPF source filename relative to --bpf-dir, e.g. bpf_lxc.c (required)")
	rootCmd.Flags().StringVar(&flagBPFDir, "bpf-dir", "bpf", "Path to bpf/ source directory")
	rootCmd.MarkFlagRequired("config")
	rootCmd.MarkFlagRequired("program")
}

func run(_ *cobra.Command, _ []string) error {
	configData, err := loadConfigMap(flagConfig)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	vp := viper.New()
	for k, v := range configData {
		vp.Set(k, v)
	}
	option.Config.Populate(vp)

	defined, undefined := config.PreprocessFlags()

	// Build unifdef args: sorted -D flags then sorted -U flags.
	args := make([]string, 0, len(defined)+len(undefined)+1)

	defSyms := make([]string, 0, len(defined))
	for sym := range defined {
		defSyms = append(defSyms, sym)
	}
	sort.Strings(defSyms)
	for _, sym := range defSyms {
		val := defined[sym]
		if val == "1" {
			args = append(args, "-D"+sym)
		} else {
			args = append(args, fmt.Sprintf("-D%s=%s", sym, val))
		}
	}

	sort.Strings(undefined)
	for _, sym := range undefined {
		args = append(args, "-U"+sym)
	}

	// unifdef reads from stdin when the filename is "-".
	args = append(args, "-")

	sourceFile := flagProgram
	if !filepath.IsAbs(sourceFile) {
		sourceFile = filepath.Join(flagBPFDir, sourceFile)
	}

	src, err := os.ReadFile(sourceFile)
	if err != nil {
		return fmt.Errorf("reading source: %w", err)
	}

	// unifdef cannot evaluate #if conditions that span multiple lines via
	// backslash continuation (documented limitation).  Join them first so
	// that multi-line conditions like
	//   #if !defined(A) || \
	//       defined(B)
	// become a single line that unifdef can evaluate.
	src = joinContinuationLines(src)

	cmd := exec.Command("unifdef", args...)
	cmd.Stdin = bytes.NewReader(src)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// unifdef exits with code 1 when it modifies the output — this is normal.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return fmt.Errorf("unifdef: %w", err)
	}
	return nil
}

// joinContinuationLines joins backslash-continued lines so that multi-line
// preprocessor directives become a single line.  Only lines ending with a
// literal backslash (after trimming the newline) are joined; the continuation
// whitespace of the following line is collapsed to a single space.
func joinContinuationLines(src []byte) []byte {
	lines := bytes.Split(src, []byte("\n"))
	out := make([]byte, 0, len(src))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		for bytes.HasSuffix(line, []byte(`\`)) && i+1 < len(lines) {
			line = append(bytes.TrimSuffix(line, []byte(`\`)), ' ')
			line = append(line, bytes.TrimLeft(lines[i+1], " \t")...)
			i++
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}

// loadConfigMap reads a YAML file and returns its key-value data. It handles
// both a full Kubernetes ConfigMap (extracts the "data" field) and a bare
// key-value YAML map.
func loadConfigMap(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Try full ConfigMap structure first.
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err == nil && len(cm.Data) > 0 {
		return cm.Data, nil
	}

	// Fall back to bare key-value map.
	var flat map[string]string
	if err := yaml.Unmarshal(raw, &flat); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	return flat, nil
}
