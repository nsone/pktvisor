/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package client

// AppMetrics represents server application information
type AppMetrics struct {
	App struct {
		Version   string  `mapstructure:"version"`
		UpTimeMin float64 `mapstructure:"up_time_min"`
	} `mapstructure:"app"`
}

// NameCount represents the count of a unique in name
type NameCount struct {
	Name     string `mapstructure:"name"`
	Estimate int64  `mapstructure:"estimate"`
}

// Rates represents a histogram of rates at various percentiles
type Rates struct {
	Live int64 `mapstructure:"live"`
	P50  int64 `mapstructure:"p50"`
	P90  int64 `mapstructure:"p90"`
	P95  int64 `mapstructure:"p95"`
	P99  int64 `mapstructure:"p99"`
}

// DHCPPayload contains the information specifically for the DNS protocol
type DHCPPayload struct {
	WirePackets struct {
		Filtered    int64 `mapstructure:"filtered"`
		Total       int64 `mapstructure:"total"`
		DeepSamples int64 `mapstructure:"deep_samples"`
		Discover    int64 `mapstructure:"discover"`
		Offer       int64 `mapstructure:"offer"`
		Request     int64 `mapstructure:"request"`
		Ack         int64 `mapstructure:"ack"`
	} `mapstructure:"wire_packets"`
	Rates struct {
		Total Rates `mapstructure:"total"`
	} `mapstructure:"rates"`
	Period PeriodPayload `mapstructure:"period"`
}

// DNSPayload contains the information specifically for the DNS protocol
type DNSPayload struct {
	WirePackets struct {
		Filtered    int64 `mapstructure:"filtered"`
		Ipv4        int64 `mapstructure:"ipv4"`
		Ipv6        int64 `mapstructure:"ipv6"`
		Queries     int64 `mapstructure:"queries"`
		Replies     int64 `mapstructure:"replies"`
		TCP         int64 `mapstructure:"tcp"`
		Total       int64 `mapstructure:"total"`
		UDP         int64 `mapstructure:"udp"`
		NoError     int64 `mapstructure:"noerror"`
		NxDomain    int64 `mapstructure:"nxdomain"`
		SrvFail     int64 `mapstructure:"srvfail"`
		Refused     int64 `mapstructure:"refused"`
		DeepSamples int64 `mapstructure:"deep_samples"`
	} `mapstructure:"wire_packets"`
	Rates struct {
		Total Rates `mapstructure:"total"`
	} `mapstructure:"rates"`
	Cardinality struct {
		Qname int64 `mapstructure:"qname"`
	} `mapstructure:"cardinality"`
	Xact struct {
		Counts struct {
			Total    int64 `mapstructure:"total"`
			TimedOut int64 `mapstructure:"timed_out"`
		} `mapstructure:"counts"`
		In struct {
			QuantilesUS struct {
				P50 int64 `mapstructure:"p50"`
				P90 int64 `mapstructure:"p90"`
				P95 int64 `mapstructure:"p95"`
				P99 int64 `mapstructure:"p99"`
			} `mapstructure:"quantiles_us"`
			TopSlow []NameCount `mapstructure:"top_slow"`
			Total   int64       `mapstructure:"total"`
		} `mapstructure:"in"`
		Out struct {
			QuantilesUS struct {
				P50 int64 `mapstructure:"p50"`
				P90 int64 `mapstructure:"p90"`
				P95 int64 `mapstructure:"p95"`
				P99 int64 `mapstructure:"p99"`
			} `mapstructure:"quantiles_us"`
			TopSlow []NameCount `mapstructure:"top_slow"`
			Total   int64       `mapstructure:"total"`
		} `mapstructure:"out"`
	} `mapstructure:"xact"`
	TopQname2   []NameCount   `mapstructure:"top_qname2"`
	TopQname3   []NameCount   `mapstructure:"top_qname3"`
	TopNX       []NameCount   `mapstructure:"top_nxdomain"`
	TopQtype    []NameCount   `mapstructure:"top_qtype"`
	TopRcode    []NameCount   `mapstructure:"top_rcode"`
	TopREFUSED  []NameCount   `mapstructure:"top_refused"`
	TopSRVFAIL  []NameCount   `mapstructure:"top_srvfail"`
	TopUDPPorts []NameCount   `mapstructure:"top_udp_ports"`
	TopOrgIDs   []NameCount   `mapstructure:"top_org_ids"`
	Period      PeriodPayload `mapstructure:"period"`
}

// PacketPayload contains information about raw packets regardless of protocol
type PacketPayload struct {
	Cardinality struct {
		DstIpsOut int64 `mapstructure:"dst_ips_out"`
		SrcIpsIn  int64 `mapstructure:"src_ips_in"`
	} `mapstructure:"cardinality"`
	Ipv4        int64 `mapstructure:"ipv4"`
	Ipv6        int64 `mapstructure:"ipv6"`
	TCP         int64 `mapstructure:"tcp"`
	Total       int64 `mapstructure:"total"`
	UDP         int64 `mapstructure:"udp"`
	In          int64 `mapstructure:"in"`
	Out         int64 `mapstructure:"out"`
	OtherL4     int64 `mapstructure:"other_l4"`
	DeepSamples int64 `mapstructure:"deep_samples"`
	Rates       struct {
		Pps_in struct {
			Live int64 `mapstructure:"live"`
			P50  int64 `mapstructure:"p50"`
			P90  int64 `mapstructure:"p90"`
			P95  int64 `mapstructure:"p95"`
			P99  int64 `mapstructure:"p99"`
		} `mapstructure:"pps_in"`
		Pps_out struct {
			Live int64 `mapstructure:"live"`
			P50  int64 `mapstructure:"p50"`
			P90  int64 `mapstructure:"p90"`
			P95  int64 `mapstructure:"p95"`
			P99  int64 `mapstructure:"p99"`
		} `mapstructure:"pps_out"`
		Pps_total struct {
			Live int64 `mapstructure:"live"`
			P50  int64 `mapstructure:"p50"`
			P90  int64 `mapstructure:"p90"`
			P95  int64 `mapstructure:"p95"`
			P99  int64 `mapstructure:"p99"`
		} `mapstructure:"pps_total"`
	} `mapstructure:"rates"`
	TopIpv4   []NameCount   `mapstructure:"top_ipv4"`
	TopIpv6   []NameCount   `mapstructure:"top_ipv6"`
	TopGeoLoc []NameCount   `mapstructure:"top_geoLoc"`
	TopASN    []NameCount   `mapstructure:"top_asn"`
	Period    PeriodPayload `mapstructure:"period"`
}

// PcapPayload contains information about pcap input stream
type PcapPayload struct {
	TcpReassemblyErrors int64 `mapstructure:"tcp_reassembly_errors"`
	IfDrops             int64 `mapstructure:"if_drops"`
	OsDrops             int64 `mapstructure:"os_drops"`
}

// PeriodPayload indicates the period of time for which a snapshot refers to
type PeriodPayload struct {
	StartTS int64 `mapstructure:"start_ts"`
	Length  int64 `mapstructure:"length"`
}

// StatSnapshot is a snapshot of a given period from pktvisord
type StatSnapshot struct {
	DNS     DNSPayload
	DHCP    DHCPPayload
	Packets PacketPayload
	Pcap    PcapPayload
}
