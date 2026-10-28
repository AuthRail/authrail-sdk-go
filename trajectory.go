package authrail

// TrajectorySnapshot asserts bounded prior reads from the authenticated task;
// the sidecar still checks them against its restart-safe ledger.
type TrajectorySnapshot struct {
	SessionID                    string         `json:"sessionId"`
	Start                        bool           `json:"start,omitempty"`
	Complete                     bool           `json:"complete"`
	PriorReadOperationVersionIDs []string       `json:"priorReadOperationVersionIds"`
	Values                       map[string]any `json:"values,omitempty"`
}
