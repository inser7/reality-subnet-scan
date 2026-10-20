//go:build linux

package main

import "syscall"

func bindControl(ifName string) (func(string, string, syscall.RawConn) error, error) {
	if ifName == "" {
		return nil, nil
	}
	if _, err := interfaceByName(ifName); err != nil {
		return nil, err
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
		})
	}, nil
}
