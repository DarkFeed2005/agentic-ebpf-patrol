// Package hunter is the Go-side client for, and shared vocabulary with,
// the Python AI Threat Hunter service (hunter/app.py).
package hunter

// Severity mirrors hunter.models.Severity (Python).
type Severity string

const (
	SeverityBenign   Severity = "benign"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Action mirrors hunter.models.Action (Python).
type Action string

const (
	ActionIgnore  Action = "ignore"
	ActionMonitor Action = "monitor"
	ActionAlert   Action = "alert"
	ActionKill    Action = "kill"
)

// Verdict is the JSON body returned by POST /v1/evaluate.
type Verdict struct {
	Severity       Severity `json:"severity"`
	Action         Action   `json:"action"`
	MitreTechnique string   `json:"mitre_technique"`
	MitreTactic    string   `json:"mitre_tactic"`
	Confidence     float64  `json:"confidence"`
	Rationale      string   `json:"rationale"`
}
