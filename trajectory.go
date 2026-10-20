package authrail

type TrajectorySnapshot struct {
	SessionID                    string         `json:"sessionId"`
	Start                        bool           `json:"start,omitempty"`
	Complete                     bool           `json:"complete"`
	PriorReadOperationVersionIDs []string       `json:"priorReadOperationVersionIds"`
	Values                       map[string]any `json:"values,omitempty"`
}
