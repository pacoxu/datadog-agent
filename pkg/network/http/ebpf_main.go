// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"unsafe"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/iovisor/gobpf/pkg/cpupossible"
	"golang.org/x/sys/unix"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	httpInFlightMap   = "http_in_flight"
	httpBatchesMap    = "http_batches"
	httpBatchStateMap = "http_batch_state"
	httpBatchEvents   = "http_batch_events"

	// ELF section of the BPF_PROG_TYPE_SOCKET_FILTER program used
	// to inspect plain HTTP traffic
	httpSocketFilterStub = "socket/http_filter_entry"
	httpSocketFilter     = "socket/http_filter"
	httpProgsMap         = "http_progs"

	// maxActive configures the maximum number of instances of the
	// kretprobe-probed functions handled simultaneously.  This value should be
	// enough for typical workloads (e.g. some amount of processes blocked on
	// the accept syscall).
	maxActive = 128

	// size of the channel containing completed http_notification_objects
	batchNotificationsChanSize = 100

	probeUID = "http"
)

type ebpfProgram struct {
	*manager.Manager
	cfg         *config.Config
	bytecode    bytecode.AssetReader
	offsets     []manager.ConstantEditor
	subprograms []subprogram
	mapCleaner  *ddebpf.MapCleaner

	batchCompletionHandler *ddebpf.PerfHandler
	mapErrTelemetryMap     *ebpf.Map
}

type subprogram interface {
	ConfigureManager(*manager.Manager)
	ConfigureOptions(*manager.Options)
	Start()
	Stop()
}

func newEBPFProgram(c *config.Config, offsets []manager.ConstantEditor, sockFD *ebpf.Map, errMap *ebpf.Map) (*ebpfProgram, error) {
	bc, err := getBytecode(c)
	if err != nil {
		return nil, err
	}

	batchCompletionHandler := ddebpf.NewPerfHandler(batchNotificationsChanSize)
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: httpInFlightMap},
			{Name: httpBatchesMap},
			{Name: httpBatchStateMap},
			{Name: sslSockByCtxMap},
			{Name: httpProgsMap},
			{Name: "ssl_read_args"},
			{Name: "bio_new_socket_args"},
			{Name: "fd_by_ssl_bio"},
			{Name: "ssl_ctx_by_pid_tgid"},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: httpBatchEvents},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 256 * os.Getpagesize(),
					Watermark:          1,
					RecordHandler:      batchCompletionHandler.RecordHandler,
					LostHandler:        batchCompletionHandler.LostHandler,
					RecordGetter:       batchCompletionHandler.RecordGetter,
				},
			},
		},
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  string(probes.TCPSendMsg),
					EBPFFuncName: "kprobe__tcp_sendmsg",
					UID:          probeUID,
				},
				KProbeMaxActive: maxActive,
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  "kretprobe/security_sock_rcv_skb",
					EBPFFuncName: "kretprobe__security_sock_rcv_skb",
					UID:          probeUID,
				},
				KProbeMaxActive: maxActive,
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  httpSocketFilterStub,
					EBPFFuncName: "socket__http_filter_entry",
					UID:          probeUID,
				},
			},
		},
	}

	sslProgram, _ := newSSLProgram(c, sockFD)
	program := &ebpfProgram{
		Manager:                mgr,
		bytecode:               bc,
		cfg:                    c,
		offsets:                offsets,
		batchCompletionHandler: batchCompletionHandler,
		subprograms:            []subprogram{sslProgram},
		mapErrTelemetryMap:     errMap,
	}

	return program, nil
}

func (e *ebpfProgram) Init() error {
	defer e.bytecode.Close()

	for _, s := range e.subprograms {
		s.ConfigureManager(e.Manager)
	}
	e.Manager.DumpHandler = dumpMapsHandler

	onlineCPUs, err := cpupossible.Get()
	if err != nil {
		return fmt.Errorf("couldn't determine number of CPUs: %w", err)
	}

	mapErrTelemetryMapKeys := buildMapErrTelemetryKeys(e.Manager)
	options := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			httpInFlightMap: {
				Type:       ebpf.Hash,
				MaxEntries: uint32(e.cfg.MaxTrackedConnections),
				EditorFlag: manager.EditMaxEntries,
			},
			httpBatchesMap: {
				Type:       ebpf.Hash,
				MaxEntries: uint32(len(onlineCPUs) * HTTPBatchPages),
				EditorFlag: manager.EditMaxEntries,
			},
		},
		TailCallRouter: []manager.TailCallRoute{
			{
				ProgArrayName: httpProgsMap,
				Key:           httpProg,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  httpSocketFilter,
					EBPFFuncName: "socket__http_filter",
				},
			},
		},
		ActivatedProbes: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  httpSocketFilterStub,
					EBPFFuncName: "socket__http_filter_entry",
					UID:          probeUID,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  string(probes.TCPSendMsg),
					EBPFFuncName: "kprobe__tcp_sendmsg",
					UID:          probeUID,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  "kretprobe/security_sock_rcv_skb",
					EBPFFuncName: "kretprobe__security_sock_rcv_skb",
					UID:          probeUID,
				},
			},
		},
		ConstantEditors: append(e.offsets, mapErrTelemetryMapKeys...),
	}
	options.MapEditors = make(map[string]*ebpf.Map)
	options.MapEditors[string(probes.MapErrTelemetryMap)] = e.mapErrTelemetryMap

	for _, s := range e.subprograms {
		s.ConfigureOptions(&options)
	}

	err = e.InitWithOptions(e.bytecode, options)
	if err != nil {
		return err
	}

	errMap, _, _ := e.GetMap(string(probes.MapErrTelemetryMap))
	initializeMapErrTelemetryMap(e.Manager, errMap)

	return nil
}

func (e *ebpfProgram) Start() error {
	err := e.Manager.Start()
	if err != nil {
		return err
	}

	for _, s := range e.subprograms {
		s.Start()
	}

	e.setupMapCleaner()

	return nil
}

func (e *ebpfProgram) Close() error {
	e.mapCleaner.Stop()
	err := e.Manager.Stop(manager.CleanAll)
	e.batchCompletionHandler.Stop()
	for _, s := range e.subprograms {
		s.Stop()
	}
	return err
}

func (e *ebpfProgram) setupMapCleaner() {
	httpMap, _, _ := e.GetMap(httpInFlightMap)
	httpMapCleaner, err := ddebpf.NewMapCleaner(httpMap, new(netebpf.ConnTuple), new(ebpfHttpTx))
	if err != nil {
		log.Errorf("error creating map cleaner: %s", err)
		return
	}

	ttl := e.cfg.HTTPIdleConnectionTTL.Nanoseconds()
	httpMapCleaner.Clean(e.cfg.HTTPMapCleanerInterval, func(now int64, key, val interface{}) bool {
		httpTxn, ok := val.(*ebpfHttpTx)
		if !ok {
			return false
		}

		if updated := int64(httpTxn.ResponseLastSeen()); updated > 0 {
			return (now - updated) > ttl
		}

		started := int64(httpTxn.RequestStarted())
		return started > 0 && (now-started) > ttl
	})

	e.mapCleaner = httpMapCleaner
}

func getBytecode(c *config.Config) (bc bytecode.AssetReader, err error) {
	if c.EnableRuntimeCompiler {
		bc, err = getRuntimeCompiledHTTP(c)
		if err != nil {
			if !c.AllowPrecompiledFallback {
				return nil, fmt.Errorf("error compiling network http tracer: %w", err)
			}
			log.Warnf("error compiling network http tracer, falling back to pre-compiled: %s", err)
		}
	}

	if bc == nil {
		bc, err = netebpf.ReadHTTPModule(c.BPFDir, c.BPFDebug)
		if err != nil {
			return nil, fmt.Errorf("could not read bpf module: %s", err)
		}
	}

	return
}
func buildMapErrTelemetryKeys(mgr *manager.Manager) []manager.ConstantEditor {
	var keys []manager.ConstantEditor

	h := fnv.New64a()
	for _, m := range mgr.Maps {
		h.Write([]byte(m.Name))
		keys = append(keys, manager.ConstantEditor{
			Name:  m.Name + "_telemetry_key",
			Value: h.Sum64(),
		})
		h.Reset()
	}

	return keys
}

type zeroArr struct {
	x1 uint32
	x2 uint32
	x3 uint32
	x4 uint32
	x5 uint32
}

func initializeMapErrTelemetryMap(mgr *manager.Manager, errMap *ebpf.Map) {
	z := new(zeroArr)
	h := fnv.New64a()

	for _, m := range mgr.Maps {
		h.Write([]byte(m.Name))
		key := h.Sum64()
		err := errMap.Put(unsafe.Pointer(&key), unsafe.Pointer(z))
		if err != nil {
			fmt.Printf("err; %v\n", err)
		}
		h.Reset()
	}
}
