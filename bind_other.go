//go:build !darwin && !linux

package main

import (
	"fmt"
	"syscall"
)

func bindControl(ifName string) (func(string, string, syscall.RawConn) error, error) {
	if ifName == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("binding to %s is supported on darwin and linux", ifName)
}
