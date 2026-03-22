package scanner

// Placeholder definitions matching the proto messages for routing protocols.
// These are used to allow compilation before the protobuf generated code is available.

type RIPInfo struct {
    Source      string `json:"source,omitempty"`
    Destination string `json:"destination,omitempty"`
    Metric      uint32 `json:"metric,omitempty"`
}

type BGPInfo struct {
    Asn        uint32   `json:"asn,omitempty"`
    NeighborIp string   `json:"neighbor_ip,omitempty"`
    Nlri       []string `json:"nlri,omitempty"`
}

type OSPFInfo struct {
    RouterId string `json:"router_id,omitempty"`
    AreaId   string `json:"area_id,omitempty"`
    LsaType  string `json:"lsa_type,omitempty"`
}

// Request/Response placeholders for RPCs

type GetRIPInfoRequest struct{}
type GetRIPInfoResponse struct{ RipInfos []RIPInfo `json:"rip_infos,omitempty"` }

type GetBGPInfoRequest struct{}
type GetBGPInfoResponse struct{ BgpInfos []BGPInfo `json:"bgp_infos,omitempty"` }

type GetOSPFInfoRequest struct{}
type GetOSPFInfoResponse struct{ OspfInfos []OSPFInfo `json:"ospf_infos,omitempty"` }
