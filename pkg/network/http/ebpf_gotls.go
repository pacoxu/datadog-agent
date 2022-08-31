// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/network/go/binversion"
	"github.com/DataDog/datadog-agent/pkg/network/http/gotls/lookup"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
)

// #include <stdlib.h>
// #include <string.h>
//
// #include "../ebpf/c/http-types.h"
import "C"

const (
	BINARY              = "/proc/134121/exe"
	probeDataMap        = "probe_data"
	readPartialCallsMap = "read_partial_calls"

	writeFuncName      = "uprobe__crypto_tls_Conn_Write"
	readFuncName       = "uprobe__crypto_tls_Conn_Read"
	readReturnFuncName = "uprobe__crypto_tls_Conn_Read__return"
	closeFuncName      = "uprobe__crypto_tls_Conn_Close"

	writeProbe      = "uprobe/crypto/tls.(*Conn).Write"
	readProbe       = "uprobe/crypto/tls.(*Conn).Read"
	readReturnProbe = "uprobe/crypto/tls.(*Conn).Read/return"
	closeProbe      = "uprobe/crypto/tls.(*Conn).Close"
)

var functionsConfig = map[string]bininspect.FunctionConfiguration{
	bininspect.WriteGoTLSFunc: {
		IncludeReturnLocations: false,
		ParamLookupFunction:    lookup.GetWriteParams,
	},
	bininspect.ReadGoTLSFunc: {
		IncludeReturnLocations: true,
		ParamLookupFunction:    lookup.GetReadParams,
	},
	bininspect.CloseGoTLSFunc: {
		IncludeReturnLocations: false,
		ParamLookupFunction:    lookup.GetCloseParams,
	},
}

var structFieldsLookupFunctions = map[bininspect.FieldIdentifier]bininspect.StructLookupFunction{
	bininspect.StructOffsetTLSConn:     lookup.GetTLSConnInnerConnOffset,
	bininspect.StructOffsetTCPConn:     lookup.GetTCPConnInnerConnOffset,
	bininspect.StructOffsetNetConnFd:   lookup.GetConnFDOffset,
	bininspect.StructOffsetNetFdPfd:    lookup.GetNetFD_PFDOffset,
	bininspect.StructOffsetPollFdSysfd: lookup.GetFD_SysfdOffset,
}

type GoTLSProgram struct {
	manager     *manager.Manager
	procRoot    string
	procMonitor struct {
		done   chan struct{}
		events chan netlink.ProcEvent
		errors chan error
	}
	probeDataMap *ebpf.Map
	inspected    map[uint64]*bininspect.Result
}

// Static evaluation to make sure we are not breaking the interface.
var _ subprogram = &GoTLSProgram{}

func NewGoTLSProgram(c *config.Config) (*GoTLSProgram, error) {
	if !c.EnableHTTPSMonitoring {
		return nil, nil
	}

	p := &GoTLSProgram{
		procRoot:  c.ProcRoot,
		inspected: make(map[uint64]*bininspect.Result),
	}
	p.procMonitor.done = make(chan struct{})
	p.procMonitor.events = make(chan netlink.ProcEvent, 10)
	p.procMonitor.errors = make(chan error, 1)
	return p, nil
}

func (p *GoTLSProgram) ConfigureManager(m *manager.Manager) {
	// TODO check if we support go TLS on the current arch
	if p == nil {
		return
	}

	p.manager = m
	p.manager.Maps = append(p.manager.Maps,
		&manager.Map{Name: probeDataMap},
		&manager.Map{Name: readPartialCallsMap})
	// Hooks will be added in runtime for each binary
}

func (p *GoTLSProgram) ConfigureOptions(options *manager.Options) {}

func (p *GoTLSProgram) Start() {
	if p == nil {
		return
	}

	var err error
	p.probeDataMap, _, err = p.manager.GetMap(probeDataMap)
	if err != nil {
		log.Errorf("could not get probe_data map: %s", err)
		return
	}

	if err := netlink.ProcEventMonitor(p.procMonitor.events, p.procMonitor.done, p.procMonitor.errors); err != nil {
		log.Errorf("could not create process monitor: %s", err)
		return
	}

	go func() {
		for {
			select {
			case event, ok := <-p.procMonitor.events:
				if !ok {
					return
				}
				// In the future Start() should just initiate the new processes listener
				// and this implementation should be done for each new process found.

				switch ev := event.Msg.(type) {
				case *netlink.ExecProcEvent:
					func() {
						exePath := filepath.Join(p.procRoot, strconv.FormatUint(uint64(ev.ProcessPid), 10), "exe")
						binPath, err := os.Readlink(exePath)
						if err != nil {
							log.Errorf("could not read binary path for pid %d: %s", ev.ProcessPid, err)
							return
						}

						var stat syscall.Stat_t
						if err = syscall.Stat(binPath, &stat); err != nil {
							log.Errorf("could not stat bin path %s: %s", binPath, err)
							return
						}

						result, ok := p.inspected[stat.Ino]
						if !ok {
							f, err := os.Open(binPath)
							if err != nil {
								log.Errorf("could not open file %s: %s", binPath, err)
								return
							}
							defer f.Close()

							elfFile, err := elf.NewFile(f)
							if err != nil {
								log.Errorf("file %s could not be parsed as elf: %s", binPath, err)
								return
							}

							result, err = bininspect.InspectNewProcessBinary(elfFile, functionsConfig, structFieldsLookupFunctions)
							if err != nil {
								if !errors.Is(err, binversion.ErrNotGoExe) {
									log.Errorf("error reading exe: %s", err)
								}

								return
							}

							// result and bin path are being passed as parameters as a preparation for the future when we will have a process
							// watcher, so we will run on more than one binary in one goTLSProgram.
							if err = p.addInspectionResultToMap(result, stat.Ino); err != nil {
								log.Error(err)
								return
							}

							p.inspected[stat.Ino] = result
						}

						p.attachHooks(result, binPath)

					}()
				}

			case err, ok := <-p.procMonitor.errors:
				if !ok {
					return
				}

				log.Errorf("process watcher error: %s", err)
			}
		}
	}()

}

func (p *GoTLSProgram) addInspectionResultToMap(result *bininspect.Result, ino uint64) error {
	probeData, err := inspectionResultToProbeData(result)
	if err != nil {
		return fmt.Errorf("error while parsing inspection result: %w", err)
	}

	err = p.probeDataMap.Put(ino, probeData)
	if err != nil {
		return fmt.Errorf("failed writing binary inspection result to map for ino %d: %w", ino, err)
	}

	return nil
}

func (p *GoTLSProgram) attachHooks(result *bininspect.Result, binPath string) {
	uid := getUID(binPath)

	for i, offset := range result.Functions[bininspect.ReadGoTLSFunc].ReturnLocations {
		probeID := manager.ProbeIdentificationPair{
			EBPFSection:  readReturnProbe,
			EBPFFuncName: readReturnFuncName,
			// Each return probe needs to have a unique uid value,
			// so add the index to the binary UID to make an overall UID.
			UID: makeReturnUID(uid, i),
		}
		if probe, found := p.manager.GetProbe(probeID); found {
			if !probe.IsRunning() {
				if err := probe.Attach(); err != nil {
					log.Errorf("error attaching probe %s: %s", p, err)
					return
				}
			}

			continue
		}

		err := p.manager.AddHook("", &manager.Probe{
			ProbeIdentificationPair: probeID,
			BinaryPath:              binPath,
			UprobeOffset:            offset,
		})

		if err != nil {
			log.Errorf("could not add hook to read return in offset %d due to: %w", offset, err)
			return
		}
	}

	probes := []*manager.Probe{
		{
			BinaryPath:   binPath,
			UprobeOffset: result.Functions[bininspect.WriteGoTLSFunc].EntryLocation,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  writeProbe,
				EBPFFuncName: writeFuncName,
				UID:          uid,
			},
		},
		{
			BinaryPath: binPath,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  readProbe,
				EBPFFuncName: readFuncName,
				UID:          uid,
			},
			UprobeOffset: result.Functions[bininspect.ReadGoTLSFunc].EntryLocation,
		},
		{
			BinaryPath: binPath,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  closeProbe,
				EBPFFuncName: closeFuncName,
				UID:          uid,
			},
			UprobeOffset: result.Functions[bininspect.CloseGoTLSFunc].EntryLocation,
		},
	}

	for _, probe := range probes {
		if p, ok := p.manager.GetProbe(probe.ProbeIdentificationPair); ok {
			if !p.IsRunning() {
				if err := p.Attach(); err != nil {
					log.Errorf("error attaching probe %s: %s", p, err)
					return
				}
			}

			continue
		}

		err := p.manager.AddHook("", probe)
		if err != nil {
			log.Errorf("could not add hook for %q in offset %d due to: %w", probe.EBPFFuncName, probe.UprobeOffset, err)
			return
		}
	}
}

func (p *GoTLSProgram) Stop() {
	if p == nil {
		return
	}

	close(p.procMonitor.done)
}
