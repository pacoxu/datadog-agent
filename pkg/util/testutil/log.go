// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package testutil

import (
	"testing"

	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// SetLogLevel will change the log level and revert to the previous level when the test finishes.
func SetLogLevel(t *testing.T, level string) {
	oldlvl, _ := log.GetLogLevel()
	t.Cleanup(func() {
		log.SetupLogger(seelog.Default, oldlvl.String())
	})
	log.SetupLogger(seelog.Default, level)
}
