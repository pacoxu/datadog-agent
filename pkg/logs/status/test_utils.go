// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package status

import (
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/metrics"
	"go.uber.org/atomic"
)

// InitStatus initialize a status builder
func InitStatus(sources *config.LogSources) {
	var isRunning *atomic.Bool = atomic.NewBool(true)
	endpoints, _ := config.BuildEndpoints(config.HTTPConnectivityFailure, "test-track", "test-proto", "test-source")
	Init(isRunning, endpoints, sources, metrics.LogsExpvars)
}
