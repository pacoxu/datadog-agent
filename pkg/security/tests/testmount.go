// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests
// +build functionaltests

package tests

import (
	"path"
	"strings"
	"syscall"
	"unsafe"
)

type testMount struct {
	target    string
	source    string
	fstype    string
	flags     uintptr
	mountOpts []string
}

func withSource(source string) func(tm *testMount) {
	return func(tm *testMount) {
		tm.source = source
	}
}

func withFSType(fstype string) func(tm *testMount) {
	return func(tm *testMount) {
		tm.fstype = fstype
	}
}

func withFlags(flags uintptr) func(tm *testMount) {
	return func(tm *testMount) {
		tm.flags = flags
	}
}

func withMountOpts(mountOpts ...string) func(tm *testMount) {
	return func(tm *testMount) {
		tm.mountOpts = mountOpts
	}
}

func newTestMount(target string, opts ...func(tm *testMount)) *testMount {
	mount := &testMount{
		target: target,
		source: "/",
	}

	for _, opt := range opts {
		opt(mount)
	}

	return mount
}

func (tm *testMount) path(filename ...string) (string, unsafe.Pointer, error) {
	components := []string{tm.target}
	components = append(components, filename...)
	path := path.Join(components...)
	filenamePtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return "", nil, err
	}
	return path, unsafe.Pointer(filenamePtr), nil
}

func (tm *testMount) mount() error {
	return syscall.Mount(tm.source, tm.target, tm.fstype, tm.flags, strings.Join(tm.mountOpts, ","))
}

func (tm *testMount) unmount(flags int) error {
	return syscall.Unmount(tm.target, flags)
}
