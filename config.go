//go:build linux

package kfeatures

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrNoKernelConfig is returned when no kernel config source is available.
var ErrNoKernelConfig = errors.New("no kernel config found")

// configSource describes a kernel config file location.
type configSource struct {
	path       string
	compressed bool
}

// readKernelConfig attempts to read and parse kernel configuration.
// It tries sources in priority order:
//  1. /proc/config.gz (requires CONFIG_IKCONFIG_PROC=y)
//  2. /boot/config-$(uname -r)
//  3. /lib/modules/$(uname -r)/config
func readKernelConfig() (*KernelConfig, error) {
	release, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	sources := []configSource{
		{path: "/proc/config.gz", compressed: true},
		{path: "/boot/config-" + release, compressed: false},
		{path: "/lib/modules/" + release + "/config", compressed: false},
	}

	var lastErr error
	for _, src := range sources {
		kc, err := parseConfigFrom(src)
		if err == nil {
			return kc, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("%w: %w", ErrNoKernelConfig, lastErr)
}

// kernelRelease returns the kernel release string (e.g., "6.17.0-1005-aws").
func kernelRelease() (string, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(uname.Release[:]), nil
}

// parseConfigFrom reads and parses a kernel config from the given source.
func parseConfigFrom(src configSource) (*KernelConfig, error) {
	f, err := os.Open(src.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	if src.compressed {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		reader = gr
	}

	return parseConfig(reader)
}

// parseConfig parses kernel configuration from a reader.
// It extracts CONFIG_* entries with =y (builtin) or =m (module) values.
func parseConfig(r io.Reader) (*KernelConfig, error) {
	raw := make(map[string]ConfigValue)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse CONFIG_FOO=value.
		if !strings.HasPrefix(line, "CONFIG_") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimPrefix(parts[0], "CONFIG_")
		value := parts[1]

		switch value {
		case "y":
			raw[key] = ConfigBuiltin
		case "m":
			raw[key] = ConfigModule
			// Other values (strings, numbers) are ignored.
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return NewKernelConfig(raw), nil
}
