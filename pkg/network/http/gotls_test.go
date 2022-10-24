// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).

// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/http/testutil"
	"github.com/stretchr/testify/require"
)

func TestHTTPGoTLSCapture(t *testing.T) {
	const ServerAddr string = "localhost:8081"
	const ExpectedOccurrences int = 10

	skipTestIfKernelNotSupported(t)

	// Given
	var closeServer func() = testutil.HTTPServer(t, ServerAddr, testutil.Options{
		EnableTLS: true,
	})

	monCfg := config.New()
	monCfg.EnableHTTPSMonitoring = true

	monitor, err := NewMonitor(monCfg, nil, nil, nil)
	require.NoError(t, err)
	require.NoError(t, monitor.Start())
	defer monitor.Stop()

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// When
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/%d/request", ServerAddr, http.StatusOK), nil)
	require.NoError(t, err)
	for i := 0; i < ExpectedOccurrences; i++ {
		resp, err := client.Do(req)
		require.NoError(t, err)

		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	closeServer()

	// Then
	occurences := 0
	require.Eventually(t, func() bool {
		stats := monitor.GetHTTPStats()
		occurences += countRequestOccurrences(stats, req)
		return occurences == ExpectedOccurrences
	}, 3*time.Second, 100*time.Millisecond, "Expected to find the request %v times, got %v captured", ExpectedOccurrences, occurences)
}
