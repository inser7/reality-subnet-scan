//go:build darwin

package main

import "syscall"

// IP_BOUND_IF is not in x/sys's portable syscall set used here.
const ipBoundIF = 25

func bindControl(ifName string) (func(string, string, syscall.RawConn) error, error) {
	if ifName == "" {
		return nil, nil
	}
	ifi, err := interfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	idx := ifi
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, idx)
		})
	}, nil
}
