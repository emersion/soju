//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"fmt"
	"syscall"
)

func bumpOpenedFileLimit() error {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return fmt.Errorf("failed to get RLIMIT_NOFILE: %v", err)
	}
	rlimit.Cur = rlimit.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return fmt.Errorf("failed to set RLIMIT_NOFILE: %v", err)
	}
	return nil
}
