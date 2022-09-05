// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/DataDog/gopsutil/process"

	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Processes holds process info indexed per PID
type Processes map[int32]*process.FilledProcess

const (
	// ProcessCacheKey is the global cache key to use for compliance processes
	ProcessCacheKey string = "compliance-processes"
)

var (
	// Fetcher is a singleton function to fetch the active processes
	Fetcher = fetchProcesses
)

// FindProcessesByName returned the list of processes with the specified name
func (p Processes) FindProcessesByName(name string) []*process.FilledProcess {
	return p.FindProcesses(func(process *process.FilledProcess) bool {
		return process.Name == name
	})
}

// FindProcesses returned the list of processes matching a specific function
func (p Processes) FindProcesses(matchFunc func(*process.FilledProcess) bool) []*process.FilledProcess {
	var results = make([]*process.FilledProcess, 0)
	for _, process := range p {
		if matchFunc(process) {
			results = append(results, process)
		}
	}

	return results
}

func fetchProcesses() (Processes, error) {
	return process.AllProcesses()
}

// GetProcesses returns all the processes in cache that do not exceed a specified duration
func GetProcesses(maxAge time.Duration) (Processes, error) {
	if value, found := cache.Cache.Get(ProcessCacheKey); found {
		return value.(Processes), nil
	}

	log.Debug("Updating process cache")
	rawProcesses, err := Fetcher()
	if err != nil {
		return nil, err
	}

	cache.Cache.Set(ProcessCacheKey, rawProcesses, maxAge)
	return rawProcesses, nil
}

// ParseProcessCmdLine parses command lines arguments into a map of flags and options.
// Parsing is far from being exhaustive, however for now it works sufficiently well
// for standard flag style command args.
func ParseProcessCmdLine(args []string) map[string]string {
	results := make(map[string]string, 0)
	pendingFlagValue := false

	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			parts := strings.SplitN(arg, "=", 2)

			// We have -xxx=yyy, considering the flag completely resolved
			if len(parts) == 2 {
				results[parts[0]] = parts[1]
			} else {
				results[parts[0]] = ""
				pendingFlagValue = true
			}
		} else {
			if pendingFlagValue {
				results[args[i-1]] = arg
			} else {
				results[arg] = ""
			}
		}
	}

	return results
}

// ValueFromProcessFlag returns the first process with the specified name and flag
func ValueFromProcessFlag(name string, flag string, cacheValidity time.Duration) (interface{}, error) {
	log.Debugf("Resolving value from process: %s, flag %s", name, flag)

	processes, err := GetProcesses(cacheValidity)
	if err != nil {
		return "", fmt.Errorf("unable to fetch processes: %w", err)
	}

	matchedProcesses := processes.FindProcessesByName(name)
	for _, mp := range matchedProcesses {
		flagValues := ParseProcessCmdLine(mp.Cmdline)
		return flagValues[flag], nil
	}

	return "", fmt.Errorf("failed to find process: %s", name)
}
