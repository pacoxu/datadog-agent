package flowaggregator

import (
	"github.com/DataDog/datadog-agent/pkg/netflow/common"
	"github.com/DataDog/datadog-agent/pkg/netflow/payload"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_buildPayload(t *testing.T) {
	tests := []struct {
		name            string
		flow            common.Flow
		expectedPayload payload.FlowPayload
	}{
		{
			name: "base case",
			flow: common.Flow{
				Namespace:       "my-namespace",
				FlowType:        common.TypeNetFlow9,
				SamplingRate:    10,
				Direction:       1,
				ExporterAddr:    []byte{127, 0, 0, 1},
				StartTimestamp:  1234568,
				EndTimestamp:    1234569,
				Bytes:           10,
				Packets:         2,
				SrcAddr:         []byte{10, 10, 10, 10},
				DstAddr:         []byte{10, 10, 10, 20},
				SrcMac:          uint64(10),
				DstMac:          uint64(20),
				SrcMask:         uint32(10),
				DstMask:         uint32(20),
				EtherType:       uint32(0x0800),
				IPProtocol:      uint32(6),
				SrcPort:         uint32(2000),
				DstPort:         uint32(80),
				InputInterface:  10,
				OutputInterface: 20,
				Tos:             3,
				NextHop:         []byte{10, 10, 10, 30},
				TCPFlags:        uint32(19), // 19 = SYN,ACK,FIN
			},
			expectedPayload: payload.FlowPayload{
				FlowType:     "netflow9",
				SamplingRate: 10,
				Direction:    "egress",
				Start:        1234568,
				End:          1234569,
				Bytes:        10,
				Packets:      2,
				EtherType:    "IPv4",
				IPProtocol:   "TCP",
				Exporter: payload.Exporter{
					IP: "127.0.0.1",
				},
				Source: payload.Endpoint{
					IP:   "10.10.10.10",
					Port: 2000,
					Mac:  "00:00:00:00:00:0a",
					Mask: "10.0.0.0/10",
				},
				Destination: payload.Endpoint{IP: "10.10.10.20",
					Port: 80,
					Mac:  "00:00:00:00:00:14",
					Mask: "10.10.0.0/20",
				},
				Ingress:   payload.ObservationPoint{Interface: payload.Interface{Index: 10}},
				Egress:    payload.ObservationPoint{Interface: payload.Interface{Index: 20}},
				Namespace: "my-namespace",
				Host:      "my-hostname",
				TCPFlags:  []string{"FIN", "SYN", "ACK"},
				NextHop: payload.NextHop{
					IP: "10.10.10.30",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowPayload := buildPayload(&tt.flow, "my-hostname")
			assert.Equal(t, tt.expectedPayload, flowPayload)
		})
	}
}