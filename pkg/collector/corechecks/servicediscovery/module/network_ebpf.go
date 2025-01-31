// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux_bpf

package module

import (
	"fmt"

	manager "github.com/DataDog/ebpf-manager"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	ebpfmaps "github.com/DataDog/datadog-agent/pkg/ebpf/maps"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const statsMapName = "network_stats"

type eBPFNetworkCollector struct {
	m        *ddebpf.Manager
	statsMap *ebpfmaps.GenericMap[NetworkStatsKey, NetworkStats]
}

func (c *eBPFNetworkCollector) setupManager(buf bytecode.AssetReader, options manager.Options) error {
	c.m = ddebpf.NewManagerWithDefault(&manager.Manager{
		Probes: []*manager.Probe{
			{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: "kretprobe__tcp_recvmsg", UID: "discovery"}},
			{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: "kretprobe__tcp_sendmsg", UID: "discovery"}},
		},
		Maps: []*manager.Map{
			{Name: statsMapName},
		},
	}, "discovery")

	if err := c.m.InitWithOptions(buf, &options); err != nil {
		return fmt.Errorf("failed to init manager: %w", err)
	}

	if err := c.m.Start(); err != nil {
		return fmt.Errorf("failed to start manager: %w", err)
	}

	statsMap, err := ebpfmaps.GetMap[NetworkStatsKey, NetworkStats](c.m.Manager, statsMapName)
	if err != nil {
		return fmt.Errorf("failed to get map '%s': %w", statsMapName, err)
	}

	c.statsMap = statsMap

	return nil
}

func getAssetName(module string, debug bool) string {
	if debug {
		return fmt.Sprintf("%s-debug.o", module)
	}

	return fmt.Sprintf("%s.o", module)
}

func newNetworkCollector(cfg *discoveryConfig) (networkCollector, error) {
	collector := eBPFNetworkCollector{}

	asset := getAssetName("discovery", cfg.BPFDebug)
	err := ddebpf.LoadCOREAsset(asset, func(ar bytecode.AssetReader, o manager.Options) error {
		return collector.setupManager(ar, o)
	})
	if err != nil {
		return nil, err
	}

	return &collector, nil
}

func (c *eBPFNetworkCollector) close() {
	if err := c.m.Stop(manager.CleanAll); err != nil {
		log.Errorf("error stopping network collector: %v", err)
	}
}

func (c *eBPFNetworkCollector) addPid(pid uint32) error {
	key := NetworkStatsKey{Pid: pid}
	var val NetworkStats

	return c.statsMap.Put(&key, &val)
}

func (c *eBPFNetworkCollector) removePid(pid uint32) error {
	key := NetworkStatsKey{Pid: pid}
	return c.statsMap.Delete(&key)
}

func (c *eBPFNetworkCollector) getStats(pid uint32) (NetworkStats, error) {
	key := NetworkStatsKey{Pid: pid}
	var val NetworkStats
	err := c.statsMap.Lookup(&key, &val)
	return val, err
}
