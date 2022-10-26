// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/testutil"
)

func TestConntrackCompile(t *testing.T) {
	testutil.SetLogLevel(t, "debug")
	cfg := config.New()
	cfg.BPFDebug = true
	cfg.RuntimeCompilerOutputDir = t.TempDir()
	_, err := getRuntimeCompiledConntracker(cfg)
	require.NoError(t, err)
}
