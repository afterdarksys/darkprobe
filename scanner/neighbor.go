package scanner

// NeighborInfo represents CDP or LLDP neighbor information.
type NeighborInfo struct {
    ChassisID    string   `json:"chassis_id"`
    PortID       string   `json:"port_id"`
    SystemName   string   `json:"system_name"`
    ManagementIP string   `json:"management_ip"`
    Capabilities []string `json:"capabilities"`
    Protocol     string   `json:"protocol"` // "CDP" or "LLDP"
}

// GetNeighbors returns the list of discovered neighbors.
func (ps *PassiveScanner) GetNeighbors() []NeighborInfo {
    return ps.neighbors
}
