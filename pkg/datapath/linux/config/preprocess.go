// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/defaults"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// PreprocessFlags returns the set of #define values and #undef symbol names
// derived from option.Config, suitable for driving unifdef. Defined contains
// all symbols with their values; undefined lists symbols that are explicitly
// disabled so that unifdef removes their dead branches.
//
// Symbols requiring live node or kernel state (IP addresses, interface
// indices) are omitted; they do not appear in #ifdef checks in BPF source.
func PreprocessFlags() (defined dpdef.Map, undefined []string) {
	defined = make(dpdef.Map)

	// Boolean feature flags: emit the symbol as defined=1 when on, or add to
	// undefined so unifdef removes the dead branch.
	boolFlag := func(cond bool, symbol string) {
		if cond {
			defined[symbol] = "1"
		} else {
			undefined = append(undefined, symbol)
		}
	}

	boolFlag(option.Config.EnableIPv4, "ENABLE_IPV4")
	boolFlag(option.Config.EnableIPv6, "ENABLE_IPV6")
	boolFlag(option.Config.EnableIPv4FragmentsTracking, "ENABLE_IPV4_FRAGMENTS")
	boolFlag(option.Config.EnableSRv6, "ENABLE_SRV6")
	boolFlag(option.Config.EnableSRv6 && option.Config.SRv6EncapMode != "reduced", "ENABLE_SRV6_SRH_ENCAP")
	boolFlag(option.Config.EnableSCTP, "ENABLE_SCTP")
	boolFlag(option.Config.EnableIPSec, "ENABLE_IPSEC")
	boolFlag(option.Config.EnableIPSec && option.Config.EnableIPSecEncryptedOverlay, "ENABLE_ENCRYPTED_OVERLAY")
	boolFlag(option.Config.EnableWireguard, "ENABLE_WIREGUARD")
	boolFlag(option.Config.EnableWireguard && option.Config.EncryptNode, "ENABLE_NODE_ENCRYPTION")
	boolFlag(option.Config.ServiceNoBackendResponse == option.ServiceNoBackendResponseReject, "SERVICE_NO_BACKEND_RESPONSE")
	boolFlag(option.Config.EnableL2Announcements, "ENABLE_L2_ANNOUNCEMENTS")
	boolFlag(option.Config.EnableEncryptionStrictMode, "ENCRYPTION_STRICT_MODE")
	boolFlag(option.Config.EnableBPFTProxy, "ENABLE_TPROXY")
	boolFlag(option.Config.EnableXDPPrefilter, "ENABLE_PREFILTER")
	boolFlag(option.Config.EnableEndpointRoutes, "ENABLE_ENDPOINT_ROUTES")
	boolFlag(option.Config.EnableEnvoyConfig, "ENABLE_L7_LB")
	boolFlag(option.Config.EnableSocketLB && option.Config.BPFSocketLBHostnsOnly, "ENABLE_SOCKET_LB_HOST_ONLY")
	boolFlag(option.Config.EnableSocketLB && !option.Config.BPFSocketLBHostnsOnly, "ENABLE_SOCKET_LB_FULL")
	boolFlag(option.Config.EnableSocketLB && option.Config.EnableSocketLBPeer, "ENABLE_SOCKET_LB_PEER")
	boolFlag(option.Config.EnableSocketLB && option.Config.EnableSocketLBTracing, "TRACE_SOCK_NOTIFY")
	boolFlag(option.Config.EnableLocalRedirectPolicy, "ENABLE_LOCAL_REDIRECT_POLICY")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableHealthDatapath, "ENABLE_HEALTH_CHECK")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableMKE && option.Config.EnableSocketLB, "ENABLE_MKE")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableRecorder, "ENABLE_CAPTURE")
	boolFlag(option.Config.EnableNodePort, "ENABLE_NODEPORT")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableNat46X64Gateway, "ENABLE_NAT_46X64_GATEWAY")
	boolFlag(option.Config.EnableNodePort && option.Config.NodePortNat46X64, "ENABLE_NAT_46X64")
	boolFlag(option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR(), "ENABLE_DSR")
	boolFlag(option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR() && option.Config.EnablePMTUDiscovery, "ENABLE_DSR_ICMP_ERRORS")
	boolFlag(option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR() && option.Config.NodePortMode == option.NodePortModeHybrid, "ENABLE_DSR_HYBRID")
	boolFlag(option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR() && option.Config.LoadBalancerModeAnnotation, "ENABLE_DSR_BYUSER")
	boolFlag(option.Config.EnableNodePort && option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled, "ENABLE_NODEPORT_ACCELERATION")
	boolFlag(option.Config.EnableNodePort && !option.Config.EnableHostLegacyRouting, "ENABLE_HOST_ROUTING")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableSVCSourceRangeCheck, "ENABLE_SRC_RANGE_CHECK")
	boolFlag(option.Config.EnableHostFirewall, "ENABLE_HOST_FIREWALL")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableBPFMasquerade && option.Config.EnableIPv4Masquerade, "ENABLE_MASQUERADE_IPV4")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableBPFMasquerade && option.Config.EnableIPv6Masquerade, "ENABLE_MASQUERADE_IPV6")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableBPFMasquerade && option.Config.EnableIPv4Masquerade && option.Config.EnableIPMasqAgent, "ENABLE_IP_MASQ_AGENT_IPV4")
	boolFlag(option.Config.EnableNodePort && option.Config.EnableBPFMasquerade && option.Config.EnableIPv6Masquerade && option.Config.EnableIPMasqAgent, "ENABLE_IP_MASQ_AGENT_IPV6")
	boolFlag(option.Config.AllowICMPFragNeeded, "ALLOW_ICMP_FRAG_NEEDED")
	boolFlag(option.Config.ClockSource == option.ClockSourceJiffies, "ENABLE_JIFFIES")
	boolFlag(option.Config.EnableIdentityMark, "ENABLE_IDENTITY_MARK")
	boolFlag(option.Config.EnableHighScaleIPcache, "ENABLE_HIGH_SCALE_IPCACHE")
	boolFlag(option.Config.EnableCustomCalls, "ENABLE_CUSTOM_CALLS")
	boolFlag(option.Config.EnableVTEP, "ENABLE_VTEP")
	boolFlag(option.Config.DisableExternalIPMitigation, "DISABLE_EXTERNAL_IP_MITIGATION")
	boolFlag(option.Config.EnableICMPRules, "ENABLE_ICMP_RULE")
	boolFlag(option.Config.TunnelingEnabled(), "TUNNEL_MODE")
	boolFlag(option.Config.PreAllocateMaps, "PREALLOCATE_MAPS")
	boolFlag(option.Config.BPFDistributedLRU, "NO_COMMON_MEM_MAPS")
	boolFlag(option.Config.EnableSessionAffinity, "ENABLE_SESSION_AFFINITY")
	boolFlag(option.Config.LoadBalancerAlgorithmAnnotation, "LB_SELECTION_PER_SERVICE")
	boolFlag(option.Config.LoadBalancerProtocolDifferentiation, "ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION")

	// Egress gateway: ENABLE_EGRESS_GATEWAY is normally injected via hive
	// NodeDefines from pkg/egressgateway, but EnableIPv4EgressGateway is the
	// controlling option.Config field.
	boolFlag(option.Config.EnableIPv4EgressGateway, "ENABLE_EGRESS_GATEWAY")

	// HAVE_ENCAP is derived in bpf/lib/common.h from ENCAP_IFINDEX,
	// ENABLE_EGRESS_GATEWAY_COMMON and (ENABLE_DSR && DSR==Geneve), none of
	// which unifdef sees in included headers.  Compute it here so unifdef can
	// resolve #ifdef HAVE_ENCAP blocks in the top-level source.
	haveEncap := option.Config.TunnelingEnabled() ||
		option.Config.EnableIPv4EgressGateway ||
		(option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR() &&
			option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve)
	boolFlag(haveEncap, "HAVE_ENCAP")

	// Cluster-aware addressing: set by the clustermesh component through hive
	// NodeDefines when inter-cluster connectivity is active.  No option.Config
	// field exists; default to undefined for single-cluster deployments.
	undefined = append(undefined, "ENABLE_CLUSTER_AWARE_ADDRESSING")

	// Multicast: set via hive NodeDefines in pkg/maps/multicast when the
	// kernel supports FnForEachMapElem.  No option.Config field exists; default
	// to undefined.
	undefined = append(undefined, "ENABLE_MULTICAST")

	// Endpoint-config symbols (normally written to ep_config.h).  unifdef
	// doesn't expand #include directives so it cannot see ep_config.h; we add
	// them here with values appropriate for a typical LXC endpoint.
	// ENABLE_ROUTING is set when the endpoint requires BPF-level routing
	// (RequireRouting()), which is true for all standard LXC endpoints.
	defined["ENABLE_ROUTING"] = "1"
	// ENABLE_ARP_RESPONDER / ENABLE_ARP_PASSTHROUGH are mutually exclusive.
	// Standard LXC endpoints use ARP responder mode.
	defined["ENABLE_ARP_RESPONDER"] = "1"
	undefined = append(undefined, "ENABLE_ARP_PASSTHROUGH")
	// LOCAL_DELIVERY_METRICS is always defined for endpoint programs.
	defined["LOCAL_DELIVERY_METRICS"] = "1"
	// DISABLE_LOOPBACK_LB is only set for host endpoint; not applicable to LXC.
	undefined = append(undefined, "DISABLE_LOOPBACK_LB")

	// ENABLE_PER_PACKET_LB is derived in bpf_lxc.c itself from a multi-line
	// #if block (which unifdef can evaluate) and then used in later #ifdef
	// blocks.  unifdef does not track in-source #define statements, so it
	// can't connect the two.  Compute the value here so all #ifdef
	// ENABLE_PER_PACKET_LB blocks are also resolved.
	//
	// The derivation in bpf_lxc.c is:
	//   #if !defined(ENABLE_SOCKET_LB_FULL) || defined(ENABLE_SOCKET_LB_HOST_ONLY)
	//       || defined(ENABLE_L7_LB) || defined(ENABLE_SCTP)
	//       || defined(ENABLE_CLUSTER_AWARE_ADDRESSING)  ← always undefined here
	//   # define ENABLE_PER_PACKET_LB 1
	perPacketLB := !option.Config.EnableSocketLB ||
		(option.Config.EnableSocketLB && option.Config.BPFSocketLBHostnsOnly) ||
		option.Config.EnableEnvoyConfig ||
		option.Config.EnableSCTP
	boolFlag(perPacketLB, "ENABLE_PER_PACKET_LB")

	// Value defines used in #if comparisons.
	const (
		dsrEncapInv    = 0
		dsrEncapNone   = 1
		dsrEncapIPIP   = 2
		dsrEncapGeneve = 3
	)
	defined["DSR_ENCAP_IPIP"] = fmt.Sprintf("%d", dsrEncapIPIP)
	defined["DSR_ENCAP_GENEVE"] = fmt.Sprintf("%d", dsrEncapGeneve)
	defined["DSR_ENCAP_NONE"] = fmt.Sprintf("%d", dsrEncapNone)
	if option.Config.EnableNodePort && option.Config.LoadBalancerUsesDSR() {
		if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchOption {
			defined["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapNone)
		} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
			defined["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapIPIP)
		} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve {
			defined["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapGeneve)
		}
	} else {
		defined["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapInv)
	}

	const (
		selectionRandom = 1
		selectionMaglev = 2
	)
	defined["LB_SELECTION_RANDOM"] = fmt.Sprintf("%d", selectionRandom)
	defined["LB_SELECTION_MAGLEV"] = fmt.Sprintf("%d", selectionMaglev)
	if option.Config.NodePortAlg == option.NodePortAlgRandom {
		defined["LB_SELECTION"] = fmt.Sprintf("%d", selectionRandom)
	} else if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		defined["LB_SELECTION"] = fmt.Sprintf("%d", selectionMaglev)
	}

	return defined, undefined
}

// WritePreprocessNodeConfig writes a node_config.h suitable for offline BPF
// source preprocessing. All defines derivable from option.Config are written
// with accurate values; anything requiring live node or kernel state (IP
// addresses, interface indices, sysctl values) uses zero/stub values that
// allow clang -E to expand #ifdef blocks correctly.
func WritePreprocessNodeConfig(w io.Writer) error {
	cDefinesMap := make(dpdef.Map)
	extraMacrosMap := make(dpdef.Map)

	fw := bufio.NewWriter(w)

	writeIncludes(w)

	// Header comment — use zero addresses as placeholders.
	fmt.Fprintf(fw, "/*\n")
	if option.Config.EnableIPv6 {
		fmt.Fprintf(fw, " cilium.v6.external.str ::\n")
		fmt.Fprintf(fw, " cilium.v6.internal.str ::\n")
		fmt.Fprintf(fw, " cilium.v6.nodeport.str []\n\n")
	}
	fmt.Fprintf(fw, " cilium.v4.external.str 0.0.0.0\n")
	fmt.Fprintf(fw, " cilium.v4.internal.str 0.0.0.0\n")
	fmt.Fprintf(fw, " cilium.v4.nodeport.str []\n\n")
	if option.Config.EnableIPv6 {
		fw.WriteString(dumpRaw(defaults.RestoreV6Addr, make(net.IP, 16)))
	}
	fw.WriteString(dumpRaw(defaults.RestoreV4Addr, net.IP{0, 0, 0, 0}))
	fmt.Fprintf(fw, " */\n\n")

	cDefinesMap["KERNEL_HZ"] = fmt.Sprintf("%d", option.Config.KernelHz)

	zeroIPv6 := make(net.IP, 16)
	zeroIPv4 := net.IP{0, 0, 0, 0}

	if option.Config.EnableIPv6 {
		extraMacrosMap["ROUTER_IP"] = "::"
		fw.WriteString(defineIPv6("ROUTER_IP", zeroIPv6))
	}

	if option.Config.EnableIPv4 {
		cDefinesMap["IPV4_GATEWAY"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(zeroIPv4))
		cDefinesMap["IPV4_LOOPBACK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(zeroIPv4))
		cDefinesMap["IPV4_MASK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(zeroIPv4))

		if option.Config.EnableIPv4FragmentsTracking {
			cDefinesMap["ENABLE_IPV4_FRAGMENTS"] = "1"
			cDefinesMap["IPV4_FRAG_DATAGRAMS_MAP"] = fragmap.MapName
			cDefinesMap["CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", option.Config.FragmentsMapEntries)
		}
	}

	if option.Config.EnableIPv6 {
		extraMacrosMap["HOST_IP"] = "::"
		fw.WriteString(defineIPv6("HOST_IP", zeroIPv6))
	}

	cDefinesMap["UNKNOWN_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameUnknown))
	cDefinesMap["HOST_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHost))
	cDefinesMap["WORLD_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorld))
	if option.Config.IsDualStack() {
		cDefinesMap["WORLD_IPV4_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorldIPv4))
		cDefinesMap["WORLD_IPV6_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorldIPv6))
	} else {
		worldID := identity.GetReservedID(labels.IDNameWorld)
		cDefinesMap["WORLD_IPV4_ID"] = fmt.Sprintf("%d", worldID)
		cDefinesMap["WORLD_IPV6_ID"] = fmt.Sprintf("%d", worldID)
	}
	cDefinesMap["HEALTH_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHealth))
	cDefinesMap["UNMANAGED_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameUnmanaged))
	cDefinesMap["INIT_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameInit))
	cDefinesMap["LOCAL_NODE_ID"] = fmt.Sprintf("%d", identity.GetLocalNodeID())
	cDefinesMap["REMOTE_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameRemoteNode))
	cDefinesMap["KUBE_APISERVER_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameKubeAPIServer))
	cDefinesMap["ENCRYPTED_OVERLAY_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameEncryptedOverlay))
	cDefinesMap["CILIUM_LB_SERVICE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.ServiceMapMaxEntries)
	cDefinesMap["CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.ServiceBackEndMapMaxEntries)
	cDefinesMap["CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.RevNatMapMaxEntries)
	cDefinesMap["CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.AffinityMapMaxEntries)
	cDefinesMap["CILIUM_LB_SOURCE_RANGE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.SourceRangeMapMaxEntries)
	cDefinesMap["CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.MaglevMapMaxEntries)
	cDefinesMap["CILIUM_LB_SKIP_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.SkipLBMapMaxEntries)

	cDefinesMap["TUNNEL_MAP"] = tunnel.MapName
	cDefinesMap["TUNNEL_ENDPOINT_MAP_SIZE"] = fmt.Sprintf("%d", tunnel.MaxEntries)
	cDefinesMap["ENDPOINTS_MAP"] = lxcmap.MapName
	cDefinesMap["ENDPOINTS_MAP_SIZE"] = fmt.Sprintf("%d", lxcmap.MaxEntries)
	cDefinesMap["METRICS_MAP"] = metricsmap.MapName
	cDefinesMap["METRICS_MAP_SIZE"] = fmt.Sprintf("%d", metricsmap.MaxEntries)
	cDefinesMap["POLICY_MAP_SIZE"] = fmt.Sprintf("%d", policymap.MaxEntries)
	cDefinesMap["AUTH_MAP"] = authmap.MapName
	cDefinesMap["AUTH_MAP_SIZE"] = fmt.Sprintf("%d", option.Config.AuthMapEntries)
	cDefinesMap["CONFIG_MAP"] = configmap.MapName
	cDefinesMap["CONFIG_MAP_SIZE"] = fmt.Sprintf("%d", configmap.MaxEntries)
	cDefinesMap["IPCACHE_MAP"] = ipcachemap.Name
	cDefinesMap["IPCACHE_MAP_SIZE"] = fmt.Sprintf("%d", ipcachemap.MaxEntries)
	cDefinesMap["NODE_MAP"] = nodemap.MapName
	cDefinesMap["NODE_MAP_V2"] = nodemap.MapNameV2
	cDefinesMap["NODE_MAP_SIZE"] = fmt.Sprintf("%d", nodemap.DefaultMaxEntries)
	cDefinesMap["WORLD_CIDRS4_MAP"] = worldcidrsmap.MapName4
	cDefinesMap["WORLD_CIDRS4_MAP_SIZE"] = fmt.Sprintf("%d", worldcidrsmap.MapMaxEntries)
	cDefinesMap["POLICY_PROG_MAP_SIZE"] = fmt.Sprintf("%d", policymap.PolicyCallMaxEntries)
	cDefinesMap["L2_RESPONSER_MAP4_SIZE"] = fmt.Sprintf("%d", l2respondermap.DefaultMaxEntries)

	if option.Config.EnableIPSec {
		cDefinesMap["ENCRYPT_MAP"] = encrypt.MapName
	}

	cDefinesMap["L2_RESPONDER_MAP4"] = l2respondermap.MapName
	cDefinesMap["CT_CONNECTION_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutTCP.Seconds()))
	cDefinesMap["CT_CONNECTION_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutAny.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCP.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCAny.Seconds()))
	cDefinesMap["CT_SERVICE_CLOSE_REBALANCE"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCPGrace.Seconds()))
	cDefinesMap["CT_SYN_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSYN.Seconds()))
	cDefinesMap["CT_CLOSE_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutFIN.Seconds()))
	cDefinesMap["CT_REPORT_INTERVAL"] = fmt.Sprintf("%d", int64(option.Config.MonitorAggregationInterval.Seconds()))
	cDefinesMap["CT_REPORT_FLAGS"] = fmt.Sprintf("%#04x", int64(option.Config.MonitorAggregationFlags))
	cDefinesMap["RATELIMIT_MAP"] = ratelimitmap.MapName
	cDefinesMap["RATELIMIT_METRICS_MAP"] = ratelimitmap.MetricsMapName
	cDefinesMap["CT_TAIL_CALL_BUFFER4"] = "cilium_tail_call_buffer4"
	cDefinesMap["CT_TAIL_CALL_BUFFER6"] = "cilium_tail_call_buffer6"
	cDefinesMap["PER_CLUSTER_CT_TCP4"] = "cilium_per_cluster_ct_tcp4"
	cDefinesMap["PER_CLUSTER_CT_TCP6"] = "cilium_per_cluster_ct_tcp6"
	cDefinesMap["PER_CLUSTER_CT_ANY4"] = "cilium_per_cluster_ct_any4"
	cDefinesMap["PER_CLUSTER_CT_ANY6"] = "cilium_per_cluster_ct_any6"
	cDefinesMap["PER_CLUSTER_SNAT_MAPPING_IPV4"] = "cilium_per_cluster_snat_v4_external"
	cDefinesMap["PER_CLUSTER_SNAT_MAPPING_IPV6"] = "cilium_per_cluster_snat_v6_external"

	if option.Config.PreAllocateMaps {
		cDefinesMap["PREALLOCATE_MAPS"] = "1"
	}
	if option.Config.BPFDistributedLRU {
		cDefinesMap["NO_COMMON_MEM_MAPS"] = "1"
	}

	cDefinesMap["EVENTS_MAP"] = eventsmap.MapName
	cDefinesMap["EVENTS_MAP_RATE_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultRateLimit)
	cDefinesMap["EVENTS_MAP_BURST_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultBurstLimit)
	cDefinesMap["SIGNAL_MAP"] = signalmap.MapName
	cDefinesMap["LB6_REVERSE_NAT_MAP"] = "cilium_lb6_reverse_nat"
	cDefinesMap["LB6_SERVICES_MAP_V2"] = "cilium_lb6_services_v2"
	cDefinesMap["LB6_BACKEND_MAP"] = "cilium_lb6_backends_v3"
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat6MapName
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat6MapEntries)
	cDefinesMap["LB4_REVERSE_NAT_MAP"] = "cilium_lb4_reverse_nat"
	cDefinesMap["LB4_SERVICES_MAP_V2"] = "cilium_lb4_services_v2"
	cDefinesMap["LB4_BACKEND_MAP"] = "cilium_lb4_backends_v3"
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat4MapName
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat4MapEntries)
	cDefinesMap["LB4_SKIP_MAP"] = lbmap.SkipLB4MapName
	cDefinesMap["LB6_SKIP_MAP"] = lbmap.SkipLB6MapName

	if option.Config.EnableSessionAffinity {
		cDefinesMap["ENABLE_SESSION_AFFINITY"] = "1"
		cDefinesMap["LB_AFFINITY_MATCH_MAP"] = lbmap.AffinityMatchMapName
		if option.Config.EnableIPv4 {
			cDefinesMap["LB4_AFFINITY_MAP"] = lbmap.Affinity4MapName
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["LB6_AFFINITY_MAP"] = lbmap.Affinity6MapName
		}
	}

	cDefinesMap["TRACE_PAYLOAD_LEN"] = fmt.Sprintf("%dULL", option.Config.TracePayloadlen)

	mtu := option.Config.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	cDefinesMap["MTU"] = fmt.Sprintf("%d", mtu)

	if option.Config.EnableIPv4 {
		cDefinesMap["ENABLE_IPV4"] = "1"
	}
	if option.Config.EnableIPv6 {
		cDefinesMap["ENABLE_IPV6"] = "1"
	}

	if option.Config.EnableSRv6 {
		cDefinesMap["ENABLE_SRV6"] = "1"
		if option.Config.SRv6EncapMode != "reduced" {
			cDefinesMap["ENABLE_SRV6_SRH_ENCAP"] = "1"
		}
	}

	if option.Config.EnableSCTP {
		cDefinesMap["ENABLE_SCTP"] = "1"
	}

	if option.Config.EnableIPSec {
		cDefinesMap["ENABLE_IPSEC"] = "1"
		if option.Config.EnableIPSecEncryptedOverlay {
			cDefinesMap["ENABLE_ENCRYPTED_OVERLAY"] = "1"
		}
	}

	if option.Config.EnableWireguard {
		cDefinesMap["ENABLE_WIREGUARD"] = "1"
		// WG_IFINDEX: stub 0, no live netlink lookup.
		cDefinesMap["WG_IFINDEX"] = "0"
		cDefinesMap["WG_PORT"] = fmt.Sprintf("%d", wgtypes.ListenPort)
		if option.Config.EncryptNode {
			cDefinesMap["ENABLE_NODE_ENCRYPTION"] = "1"
		}
	}

	if option.Config.ServiceNoBackendResponse == option.ServiceNoBackendResponseReject {
		cDefinesMap["SERVICE_NO_BACKEND_RESPONSE"] = "1"
	}

	if option.Config.EnableL2Announcements {
		cDefinesMap["ENABLE_L2_ANNOUNCEMENTS"] = "1"
		cDefinesMap["L2_ANNOUNCEMENTS_MAX_LIVENESS"] = fmt.Sprintf("%dULL", option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	if option.Config.EnableEncryptionStrictMode {
		cDefinesMap["ENCRYPTION_STRICT_MODE"] = "1"
		cDefinesMap["STRICT_IPV4_NET"] = fmt.Sprintf("%#x", byteorder.NetIPAddrToHost32(option.Config.EncryptionStrictModeCIDR.Addr()))
		cDefinesMap["STRICT_IPV4_NET_SIZE"] = fmt.Sprintf("%d", option.Config.EncryptionStrictModeCIDR.Bits())
		// IPV4_ENCRYPT_IFACE: stub 0, no live node IP.
		cDefinesMap["IPV4_ENCRYPT_IFACE"] = "0"
	}

	if option.Config.EnableBPFTProxy {
		cDefinesMap["ENABLE_TPROXY"] = "1"
	}
	if option.Config.EnableXDPPrefilter {
		cDefinesMap["ENABLE_PREFILTER"] = "1"
	}
	if option.Config.EnableEndpointRoutes {
		cDefinesMap["ENABLE_ENDPOINT_ROUTES"] = "1"
	}
	if option.Config.EnableEnvoyConfig {
		cDefinesMap["ENABLE_L7_LB"] = "1"
	}

	if option.Config.EnableSocketLB {
		if option.Config.BPFSocketLBHostnsOnly {
			cDefinesMap["ENABLE_SOCKET_LB_HOST_ONLY"] = "1"
		} else {
			cDefinesMap["ENABLE_SOCKET_LB_FULL"] = "1"
		}
		if option.Config.EnableSocketLBPeer {
			cDefinesMap["ENABLE_SOCKET_LB_PEER"] = "1"
		}
		if option.Config.EnableSocketLBTracing {
			cDefinesMap["TRACE_SOCK_NOTIFY"] = "1"
		}
		// HOST_NETNS_COOKIE: skip, requires live getsockopt call.
	}

	if option.Config.EnableLocalRedirectPolicy {
		cDefinesMap["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
	}

	cDefinesMap["NAT_46X64_PREFIX_0"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_1"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_2"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_3"] = "0"

	if option.Config.EnableNodePort {
		if option.Config.EnableHealthDatapath {
			cDefinesMap["ENABLE_HEALTH_CHECK"] = "1"
		}
		if option.Config.EnableMKE && option.Config.EnableSocketLB {
			cDefinesMap["ENABLE_MKE"] = "1"
			cDefinesMap["MKE_HOST"] = fmt.Sprintf("%d", option.HostExtensionMKE)
		}
		if option.Config.EnableRecorder {
			cDefinesMap["ENABLE_CAPTURE"] = "1"
			if option.Config.EnableIPv4 {
				cDefinesMap["CAPTURE4_RULES"] = recorder.MapNameWcard4
				cDefinesMap["CAPTURE4_SIZE"] = fmt.Sprintf("%d", recorder.MapSize)
			}
			if option.Config.EnableIPv6 {
				cDefinesMap["CAPTURE6_RULES"] = recorder.MapNameWcard6
				cDefinesMap["CAPTURE6_SIZE"] = fmt.Sprintf("%d", recorder.MapSize)
			}
		}
		cDefinesMap["ENABLE_NODEPORT"] = "1"
		if option.Config.EnableIPv4 {
			cDefinesMap["NODEPORT_NEIGH4"] = neighborsmap.Map4Name
			cDefinesMap["NODEPORT_NEIGH4_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
			if option.Config.EnableHealthDatapath {
				cDefinesMap["LB4_HEALTH_MAP"] = lbmap.HealthProbe4MapName
			}
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["NODEPORT_NEIGH6"] = neighborsmap.Map6Name
			cDefinesMap["NODEPORT_NEIGH6_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
			if option.Config.EnableHealthDatapath {
				cDefinesMap["LB6_HEALTH_MAP"] = lbmap.HealthProbe6MapName
			}
		}
		if option.Config.EnableNat46X64Gateway {
			cDefinesMap["ENABLE_NAT_46X64_GATEWAY"] = "1"
			base := option.Config.IPv6NAT46x64CIDRBase.AsSlice()
			cDefinesMap["NAT_46X64_PREFIX_0"] = fmt.Sprintf("%d", base[0])
			cDefinesMap["NAT_46X64_PREFIX_1"] = fmt.Sprintf("%d", base[1])
			cDefinesMap["NAT_46X64_PREFIX_2"] = fmt.Sprintf("%d", base[2])
			cDefinesMap["NAT_46X64_PREFIX_3"] = fmt.Sprintf("%d", base[3])
		}
		if option.Config.NodePortNat46X64 {
			cDefinesMap["ENABLE_NAT_46X64"] = "1"
		}
		const (
			dsrEncapInv = iota
			dsrEncapNone
			dsrEncapIPIP
			dsrEncapGeneve
		)
		cDefinesMap["DSR_ENCAP_IPIP"] = fmt.Sprintf("%d", dsrEncapIPIP)
		cDefinesMap["DSR_ENCAP_GENEVE"] = fmt.Sprintf("%d", dsrEncapGeneve)
		cDefinesMap["DSR_ENCAP_NONE"] = fmt.Sprintf("%d", dsrEncapNone)
		if option.Config.LoadBalancerUsesDSR() {
			cDefinesMap["ENABLE_DSR"] = "1"
			if option.Config.EnablePMTUDiscovery {
				cDefinesMap["ENABLE_DSR_ICMP_ERRORS"] = "1"
			}
			if option.Config.NodePortMode == option.NodePortModeHybrid {
				cDefinesMap["ENABLE_DSR_HYBRID"] = "1"
			} else if option.Config.LoadBalancerModeAnnotation {
				cDefinesMap["ENABLE_DSR_HYBRID"] = "1"
				cDefinesMap["ENABLE_DSR_BYUSER"] = "1"
			}
			if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchOption {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapNone)
			} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapIPIP)
			} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapGeneve)
			}
		} else {
			cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapInv)
		}
		if option.Config.EnableIPv4 {
			if option.Config.LoadBalancerRSSv4CIDR != "" {
				ipv4 := byteorder.NetIPv4ToHost32(option.Config.LoadBalancerRSSv4.IP)
				ones, _ := option.Config.LoadBalancerRSSv4.Mask.Size()
				cDefinesMap["IPV4_RSS_PREFIX"] = fmt.Sprintf("%d", ipv4)
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = fmt.Sprintf("%d", ones)
			} else {
				cDefinesMap["IPV4_RSS_PREFIX"] = "IPV4_DIRECT_ROUTING"
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = "32"
			}
		}
		if option.Config.EnableIPv6 {
			if option.Config.LoadBalancerRSSv6CIDR != "" {
				ipv6 := option.Config.LoadBalancerRSSv6.IP
				ones, _ := option.Config.LoadBalancerRSSv6.Mask.Size()
				extraMacrosMap["IPV6_RSS_PREFIX"] = ipv6.String()
				fw.WriteString(FmtDefineAddress("IPV6_RSS_PREFIX", ipv6))
				cDefinesMap["IPV6_RSS_PREFIX_BITS"] = fmt.Sprintf("%d", ones)
			} else {
				cDefinesMap["IPV6_RSS_PREFIX"] = "IPV6_DIRECT_ROUTING"
				cDefinesMap["IPV6_RSS_PREFIX_BITS"] = "128"
			}
		}
		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			cDefinesMap["ENABLE_NODEPORT_ACCELERATION"] = "1"
		}
		if !option.Config.EnableHostLegacyRouting {
			cDefinesMap["ENABLE_HOST_ROUTING"] = "1"
		}
		if option.Config.EnableSVCSourceRangeCheck {
			cDefinesMap["ENABLE_SRC_RANGE_CHECK"] = "1"
			if option.Config.EnableIPv4 {
				cDefinesMap["LB4_SRC_RANGE_MAP"] = lbmap.SourceRange4MapName
				cDefinesMap["LB4_SRC_RANGE_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.SourceRangeMapMaxEntries)
			}
			if option.Config.EnableIPv6 {
				cDefinesMap["LB6_SRC_RANGE_MAP"] = lbmap.SourceRange6MapName
				cDefinesMap["LB6_SRC_RANGE_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.SourceRangeMapMaxEntries)
			}
		}
		cDefinesMap["NODEPORT_PORT_MIN"] = fmt.Sprintf("%d", option.Config.NodePortMin)
		cDefinesMap["NODEPORT_PORT_MAX"] = fmt.Sprintf("%d", option.Config.NodePortMax)
		cDefinesMap["NODEPORT_PORT_MIN_NAT"] = fmt.Sprintf("%d", option.Config.NodePortMax+1)
		cDefinesMap["NODEPORT_PORT_MAX_NAT"] = strconv.Itoa(NodePortMaxNAT)
	}

	// No native devices: generate empty-switch stubs.
	macByIfIndexMacro, isL3DevMacro, err := devMacros(nil)
	if err != nil {
		return fmt.Errorf("generating device macros: %w", err)
	}
	cDefinesMap["NATIVE_DEV_MAC_BY_IFINDEX(IFINDEX)"] = macByIfIndexMacro
	cDefinesMap["IS_L3_DEV(ifindex)"] = isL3DevMacro

	const (
		selectionRandom = iota + 1
		selectionMaglev
	)
	cDefinesMap["LB_SELECTION_RANDOM"] = fmt.Sprintf("%d", selectionRandom)
	cDefinesMap["LB_SELECTION_MAGLEV"] = fmt.Sprintf("%d", selectionMaglev)
	if option.Config.LoadBalancerAlgorithmAnnotation {
		cDefinesMap["LB_SELECTION_PER_SERVICE"] = "1"
	}
	if option.Config.NodePortAlg == option.NodePortAlgRandom {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionRandom)
	} else if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionMaglev)
	}

	if option.Config.LoadBalancerAlgorithmAnnotation || option.Config.NodePortAlg == option.NodePortAlgMaglev {
		cDefinesMap["LB_MAGLEV_LUT_SIZE"] = fmt.Sprintf("%d", maglev.DefaultTableSize)
		if option.Config.EnableIPv6 {
			cDefinesMap["LB6_MAGLEV_MAP_OUTER"] = lbmap.MaglevOuter6MapName
		}
		if option.Config.EnableIPv4 {
			cDefinesMap["LB4_MAGLEV_MAP_OUTER"] = lbmap.MaglevOuter4MapName
		}
	}
	// Maglev hash seeds: use 0 stubs, no live UUID source.
	cDefinesMap["HASH_INIT4_SEED"] = "0"
	cDefinesMap["HASH_INIT6_SEED"] = "0"

	// Direct routing device: not available offline; use zero stubs.
	cDefinesMap["DIRECT_ROUTING_DEV_IFINDEX"] = "0"
	if option.Config.EnableIPv4 {
		cDefinesMap["IPV4_DIRECT_ROUTING"] = "0"
	}
	if option.Config.EnableIPv6 {
		extraMacrosMap["IPV6_DIRECT_ROUTING"] = "::"
		fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", zeroIPv6))
	}

	if option.Config.EnableHostFirewall {
		cDefinesMap["ENABLE_HOST_FIREWALL"] = "1"
	}

	if option.Config.EnableIPSec {
		// IPV4_ENCRYPT_IFACE: stub 0, no live node IP.
		cDefinesMap["IPV4_ENCRYPT_IFACE"] = "0"
	}

	if option.Config.EnableNodePort {
		if option.Config.EnableIPv4 {
			cDefinesMap["SNAT_MAPPING_IPV4"] = nat.MapNameSnat4Global
			cDefinesMap["SNAT_MAPPING_IPV4_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["SNAT_MAPPING_IPV6"] = nat.MapNameSnat6Global
			cDefinesMap["SNAT_MAPPING_IPV6_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
		}

		if option.Config.EnableBPFMasquerade {
			if option.Config.EnableIPv4Masquerade {
				cDefinesMap["ENABLE_MASQUERADE_IPV4"] = "1"
				if option.Config.EnableIPMasqAgent {
					cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV4"] = "1"
					cDefinesMap["IP_MASQ_AGENT_IPV4"] = ipmasq.MapNameIPv4
					if option.Config.IPv4NativeRoutingCIDR != nil {
						cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR"] =
							fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(option.Config.IPv4NativeRoutingCIDR.IP))
						ones, _ := option.Config.IPv4NativeRoutingCIDR.Mask.Size()
						cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR_LEN"] = fmt.Sprintf("%d", ones)
					}
				}
				// NativeRoutingCIDRIPv4 from LocalNodeConfiguration not available offline; skip.
			}
			if option.Config.EnableIPv6Masquerade {
				cDefinesMap["ENABLE_MASQUERADE_IPV6"] = "1"
				if option.Config.EnableIPMasqAgent {
					cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV6"] = "1"
					cDefinesMap["IP_MASQ_AGENT_IPV6"] = ipmasq.MapNameIPv6
					if option.Config.IPv6NativeRoutingCIDR != nil {
						extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR"] = option.Config.IPv6NativeRoutingCIDR.IP.String()
						fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR", option.Config.IPv6NativeRoutingCIDR.IP))
						extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR_MASK"] = option.Config.IPv6NativeRoutingCIDR.Mask.String()
						fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR_MASK", option.Config.IPv6NativeRoutingCIDR.Mask))
					}
				}
				// NativeRoutingCIDRIPv6 from LocalNodeConfiguration not available offline; skip.
			}
		}

		ctmap.WriteBPFMacros(fw, nil)
	}

	if option.Config.AllowICMPFragNeeded {
		cDefinesMap["ALLOW_ICMP_FRAG_NEEDED"] = "1"
	}
	if option.Config.ClockSource == option.ClockSourceJiffies {
		cDefinesMap["ENABLE_JIFFIES"] = "1"
	}
	if option.Config.EnableIdentityMark {
		cDefinesMap["ENABLE_IDENTITY_MARK"] = "1"
	}
	if option.Config.EnableHighScaleIPcache {
		cDefinesMap["ENABLE_HIGH_SCALE_IPCACHE"] = "1"
	}
	if option.Config.EnableCustomCalls {
		cDefinesMap["ENABLE_CUSTOM_CALLS"] = "1"
	}
	if option.Config.EnableVTEP {
		cDefinesMap["ENABLE_VTEP"] = "1"
		cDefinesMap["VTEP_MAP"] = vtep.Name
		cDefinesMap["VTEP_MAP_SIZE"] = fmt.Sprintf("%d", vtep.MaxEntries)
		cDefinesMap["VTEP_MASK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask)))
	}

	// VLAN_FILTER: no live netlink; always return false.
	cDefinesMap["VLAN_FILTER(ifindex, vlan_id)"] = "return false"

	if option.Config.DisableExternalIPMitigation {
		cDefinesMap["DISABLE_EXTERNAL_IP_MITIGATION"] = "1"
	}
	if option.Config.EnableICMPRules {
		cDefinesMap["ENABLE_ICMP_RULE"] = "1"
	}

	cDefinesMap["CIDR_IDENTITY_RANGE_START"] = fmt.Sprintf("%d", identity.MinLocalIdentity)
	cDefinesMap["CIDR_IDENTITY_RANGE_END"] = fmt.Sprintf("%d", identity.MaxLocalIdentity)

	if option.Config.TunnelingEnabled() {
		cDefinesMap["TUNNEL_MODE"] = "1"
	}

	// cilium_net / cilium_host links: stub zeros, no live netlink.
	cDefinesMap["CILIUM_NET_MAC"] = fmt.Sprintf("{.addr=%s}", "{0x0,0x0,0x0,0x0,0x0,0x0}")
	cDefinesMap["HOST_IFINDEX"] = "0"
	cDefinesMap["HOST_IFINDEX_MAC"] = fmt.Sprintf("{.addr=%s}", "{0x0,0x0,0x0,0x0,0x0,0x0}")
	cDefinesMap["CILIUM_IFINDEX"] = "0"

	// Ephemeral port range minimum: stub with common Linux default.
	cDefinesMap["EPHEMERAL_MIN"] = "32768"

	// nodeExtraDefines / nodeExtraDefineFns: not available offline; skip.

	if option.Config.EnableHealthDatapath {
		if option.Config.IPv4Enabled() {
			cDefinesMap["ENCAP4_IFINDEX"] = "0"
		}
		if option.Config.IPv6Enabled() {
			cDefinesMap["ENCAP6_IFINDEX"] = "0"
		}
	}

	cDefinesMap["CLUSTER_ID_MAX"] = fmt.Sprintf("%d", option.Config.MaxConnectedClusters)

	if option.Config.LoadBalancerProtocolDifferentiation {
		cDefinesMap["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"
	}

	fmt.Fprint(fw, declareConfig("identity_length", identity.GetClusterIDShift(), "Identity length in bits"))
	fmt.Fprint(fw, assignConfig("identity_length", identity.GetClusterIDShift()))
	fmt.Fprint(fw, declareConfig("interface_ifindex", uint32(0), "ifindex of the interface the bpf program is attached to"))
	cDefinesMap["THIS_INTERFACE_IFINDEX"] = "CONFIG(interface_ifindex)"

	keys := make([]string, 0, len(cDefinesMap))
	for key := range cDefinesMap {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(fw, "#define %s %s\n", key, cDefinesMap[key])
	}

	for key, value := range extraMacrosMap {
		cDefinesMap[key] = value
	}

	jsonBytes, err := json.Marshal(cDefinesMap)
	if err == nil {
		encodedConfig := base64.StdEncoding.EncodeToString(jsonBytes)
		fmt.Fprintf(fw, "\n// JSON_OUTPUT: %s\n", encodedConfig)
	}

	return fw.Flush()
}

// WritePreprocessEndpointConfig writes a minimal ep_config.h with stub values
// for per-endpoint defines. Accurate enough for #ifdef expansion; not suitable
// for producing a real BPF object.
func WritePreprocessEndpointConfig(w io.Writer, isHost bool) error {
	fw := bufio.NewWriter(w)

	writeIncludes(w)

	if isHost {
		if option.Config.EnableBPFMasquerade {
			if option.Config.EnableIPv4Masquerade {
				fmt.Fprint(fw, defineIPv4("IPV4_MASQUERADE", []byte{1, 1, 1, 1}))
			}
			if option.Config.EnableIPv6Masquerade {
				fmt.Fprint(fw, defineIPv6("IPV6_MASQUERADE", make([]byte, 16)))
			}
		}
		fmt.Fprint(fw, defineUint32("SECCTX_FROM_IPCACHE", 1))
	} else {
		if option.Config.EnableIPv6 {
			fmt.Fprint(fw, defineIPv6("LXC_IP", make([]byte, 16)))
		}
		fmt.Fprint(fw, defineIPv4("LXC_IPV4", []byte{0, 0, 0, 0}))
		fmt.Fprint(fw, defineUint16("LXC_ID", 1))
	}

	fmt.Fprint(fw, defineMAC("THIS_INTERFACE_MAC", nil))
	fmt.Fprint(fw, defineUint64("ENDPOINT_NETNS_COOKIE", 0))
	fmt.Fprint(fw, defineUint32("SECLABEL", 1))
	fmt.Fprint(fw, defineUint32("SECLABEL_IPV4", 1))
	fmt.Fprint(fw, defineUint32("SECLABEL_IPV6", 1))
	fmt.Fprint(fw, defineUint32("POLICY_VERDICT_LOG_FILTER", 0))

	const stubEPID = uint16(1)
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", bpf.LocalMapName(policymap.MapName, stubEPID))
	callsMapName := callsmap.MapName
	if isHost {
		callsMapName = callsmap.HostMapName
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", bpf.LocalMapName(callsMapName, stubEPID))

	// Template config stubs.
	fmt.Fprint(fw, "#define HOST_EP_ID 1\n")
	if isHost {
		fmt.Fprint(fw, "#define HOST_ENDPOINT 1\n")
		if option.Config.EnableNodePort {
			fmt.Fprint(fw, "#define DISABLE_LOOPBACK_LB 1\n")
		}
	}
	fmt.Fprint(fw, "#define ENABLE_ARP_RESPONDER 1\n")
	fmt.Fprint(fw, "#define LOCAL_DELIVERY_METRICS 1\n")

	ctmap.WriteBPFMacros(fw, nil)

	return fw.Flush()
}
