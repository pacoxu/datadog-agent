// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package orchestrator

import (
	"time"

	model "github.com/DataDog/agent-payload/v5/process"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	"github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	defaultFlushManifestTime = 20 * time.Second
	BufferManifest           = true
)

// ManifestBuffer is a buffer of manifest sent from all collectors
// It has a slice bufferedManifests used to buffer manifest and stop channel
// ManifestBuffer is started as a dedicated thread each time CollectorBundle runs a check
// and gets stopped after the check is done.
type ManifestBuffer struct {
	Cfg               *collectors.ManifestBufferConfig
	bufferedManifests []interface{}
	stopCh            chan struct{}
}

// NewManifestBuffer returns a new ManifestBuffer
func NewManifestBuffer(chk *OrchestratorCheck) *ManifestBuffer {
	manifestBuffer := &ManifestBuffer{
		Cfg: &collectors.ManifestBufferConfig{
			ClusterID:                chk.clusterID,
			KubeClusterName:          chk.orchestratorConfig.KubeClusterName,
			MsgGroupRef:              chk.groupID,
			MaxPerMessage:            chk.orchestratorConfig.MaxPerMessage,
			MaxWeightPerMessageBytes: chk.orchestratorConfig.MaxWeightPerMessageBytes,
			ManifestChan:             make(chan *model.Manifest),
			BufferedManifestEnabled:  BufferManifest,
			MaxBufferedManifests:     2 * chk.orchestratorConfig.MaxPerMessage,
		},
		stopCh: make(chan struct{}),
	}
	manifestBuffer.bufferedManifests = make([]interface{}, 0, manifestBuffer.Cfg.MaxBufferedManifests)

	return manifestBuffer
}

// flushManifest flushes manifests by chunking them first then sending them to the sender
func (cb *ManifestBuffer) flushManifest(sender aggregator.Sender) {
	manifests := cb.bufferedManifests
	cb.bufferedManifests = []interface{}{}
	ctx := &processors.ProcessorContext{
		ClusterID:  cb.Cfg.ClusterID,
		MsgGroupID: cb.Cfg.MsgGroupRef.Inc(),
		Cfg: &config.OrchestratorConfig{
			KubeClusterName:          cb.Cfg.KubeClusterName,
			MaxPerMessage:            cb.Cfg.MaxPerMessage,
			MaxWeightPerMessageBytes: cb.Cfg.MaxWeightPerMessageBytes,
		},
	}
	manifestMessages := processors.ChunkManifest(ctx, manifests)

	sender.OrchestratorManifest(manifestMessages, cb.Cfg.ClusterID)

}

// appendManifest appends manifest into the buffer
// If buffer is full, it will flush the buffer first then append the manifest
func (cb *ManifestBuffer) appendManifest(m *model.Manifest, sender aggregator.Sender) {
	if len(cb.bufferedManifests) >= cb.Cfg.MaxBufferedManifests {
		cb.flushManifest(sender)
	}

	cb.bufferedManifests = append(cb.bufferedManifests, m)
}

// Start is to start a thread to buffer manifest and send them
// It flushes manifests every defaultFlushManifestTime
func (cb *ManifestBuffer) Start(sender aggregator.Sender) {
	ticker := time.NewTicker(defaultFlushManifestTime)
	go func() {
		wait := true
		for wait {
			select {
			case msg, ok := <-cb.Cfg.ManifestChan:
				if !ok {
					log.Warnf("Fail to read orchestrator manifest from channel")
					continue
				}
				cb.appendManifest(msg, sender)
			case <-ticker.C:
				cb.flushManifest(sender)
			case <-cb.stopCh:
				cb.flushManifest(sender)
				wait = false
			}
		}
	}()
}

// Stop is to kill the thread collecting manifest
func (cb *ManifestBuffer) Stop() {
	cb.stopCh <- struct{}{}
}
