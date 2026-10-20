package main

import "syscall"

// syscallRaw is the Control callback type shared with platform bind files.
type syscallRaw = syscall.RawConn
