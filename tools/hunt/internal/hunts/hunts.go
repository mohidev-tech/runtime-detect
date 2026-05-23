// Package hunts is detection-as-code. Each Hunt is a LogQL query + a
// success criterion, with the same data shape across every hunt so the
// CLI output stays uniform.
//
// Adding a hunt is one entry in All(). The goal is "investigators can read
// a hunt and know exactly what it does without reading the LogQL spec."
package hunts

type Hunt struct {
	ID          string // short stable ID
	Title       string
	Description string
	LogQL       string
	// MinHits is the threshold above which a hunt is flagged as positive.
	// Most are >0 (any hit is interesting). Some are >5 (only repeated hits
	// are signal — single-shot noise is filtered out).
	MinHits int
	Tags    []string
}

func All() []Hunt {
	return []Hunt{
		{
			ID:    "HUNT-001",
			Title: "Shell spawned in any app container",
			Description: "Falco rule 'Shell spawned in app container' fired at least once in the lookback window. " +
				"Investigate the pod and the kubectl-exec audit trail.",
			LogQL:   `{app="falco", priority="Critical"} |= "Shell opened in app container"`,
			MinHits: 1,
			Tags:    []string{"mitre_execution", "T1059"},
		},
		{
			ID:    "HUNT-002",
			Title: "Write to K8s secrets/config paths",
			Description: "Any write under /var/run/secrets/kubernetes.io or /etc/kubernetes from inside a container. " +
				"The SA token mount is RO; writes there indicate tampering or a misconfigured init script.",
			LogQL:   `{app="falco"} |= "Write to K8s secrets/config path"`,
			MinHits: 1,
			Tags:    []string{"mitre_persistence", "T1098"},
		},
		{
			ID:    "HUNT-003",
			Title: "Sensitive file read (/etc/shadow, /etc/sudoers)",
			Description: "No legit container reads /etc/shadow. Single hit = investigate; repeated hits = active enum.",
			LogQL:   `{app="falco"} |= "Sensitive file read in container"`,
			MinHits: 1,
			Tags:    []string{"credential_access", "T1003"},
		},
		{
			ID:    "HUNT-004",
			Title: "Outbound traffic to known-bad destination",
			Description: "Container connected to a suspicious_domains entry. IOC-driven; threshold of >0 because " +
				"the list is curated, not heuristic.",
			LogQL:   `{app="falco"} |= "suspicious destination"`,
			MinHits: 1,
			Tags:    []string{"command_and_control"},
		},
		{
			ID:    "HUNT-005",
			Title: "Mount syscall inside container (escape precursor)",
			Description: "Mount inside an app container is almost never legit. Container-escape attempts " +
				"frequently mount the host root or /proc.",
			LogQL:   `{app="falco"} |= "Mount syscall in container"`,
			MinHits: 1,
			Tags:    []string{"container_escape", "T1611"},
		},
		{
			ID:    "HUNT-006",
			Title: "Burst of warnings from one pod",
			Description: "More than 5 WARNING events from a single pod in the lookback window. " +
				"Catches scenarios where individual events are tolerated but volume is not.",
			LogQL:   `sum by (k8s_pod_name) (count_over_time({app="falco", priority="Warning"} [15m])) > 5`,
			MinHits: 1,
			Tags:    []string{"behavioral"},
		},
	}
}
