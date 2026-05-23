# 🛰️ runtime-detect

> **Cloud-native runtime detection: Falco eBPF + Loki + a Go hunt CLI. The attack-sim script trips every rule on purpose; the verify-detect script proves every trip made it into Loki.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Falco 0.38+](https://img.shields.io/badge/Falco-0.38+-00BFFB)](https://falco.org/)
[![Loki 3.0+](https://img.shields.io/badge/Loki-3.0+-F46800)](https://grafana.com/oss/loki/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-A41E22)](https://attack.mitre.org/)

---

## What it does (real terminal output)

```
$ ./scripts/attack-sim.sh
==> [1] spawn shell in app container (HUNT-001)
==> [2] write to /var/run/secrets/kubernetes.io (HUNT-002)
==> [3] read /etc/shadow (HUNT-003)
==> [4] DNS lookup of evil.attacker.invalid (HUNT-004)
==> [5] mount inside container (HUNT-005)
==> Wait ~10s for events to flow through Falco -> sidekick -> Loki ...
==> Done.

$ ./scripts/verify-detect.sh
hunts run over [2026-05-23T20:14:32Z, 2026-05-23T20:24:32Z]

FIRED  HUNT-001  Shell spawned in any app container  (hits=3)
       first: 2026-05-23T20:23:08Z   last: 2026-05-23T20:23:09Z
       > {"output":"Shell opened in app container ...","priority":"Critical","rule":"Shell spawned in app container","time":"..."}

FIRED  HUNT-003  Sensitive file read (/etc/shadow, /etc/sudoers)  (hits=1)
       first: 2026-05-23T20:23:11Z   last: 2026-05-23T20:23:11Z
       > {"output":"Sensitive file read in container ...","priority":"Critical","rule":"Sensitive file read inside container", ...}

FIRED  HUNT-004  Outbound traffic to known-bad destination  (hits=1)
FIRED  HUNT-005  Mount syscall inside container (escape precursor)  (hits=1)
clean  HUNT-002  Write to K8s secrets/config paths
clean  HUNT-006  Burst of warnings from one pod

summary: 4/6 hunts fired
```

The lab is "working" when **the attacks succeed at tripping the right rules** AND **verify-detect can prove every trip landed in Loki.**

---

## The detection-as-code idea

Falco fires events into Loki labeled `app=falco`. The `hunt` CLI runs a fixed set of LogQL queries (one per hunt) and reports which ones matched. Each hunt is a single Go struct — clear, reviewable, version-controlled.

```go
{
  ID:    "HUNT-001",
  Title: "Shell spawned in any app container",
  LogQL: `{app="falco", priority="Critical"} |= "Shell opened in app container"`,
  Tags:  []string{"mitre_execution", "T1059"},
}
```

Adding a new hunt is one entry. The CI runs hunts on a schedule; the same binary works for ad-hoc threat-hunting from a laptop.

---

## Why you want this

| | **runtime-detect** | Falco + stdout | Sysdig Secure | Datadog Cloud SIEM |
|---|---|---|---|---|
| **Price** | Free (Apache 2.0) | Free | $$$ enterprise | $$$ per host |
| **Custom rules included** | ✅ 5 K8s-tuned rules | ⚠️ default ruleset only | ✅ | ⚠️ premium tier |
| **Event routing** | ✅ falcosidekick → Loki | ❌ stdout only | ✅ proprietary | ✅ proprietary |
| **Hunt-as-code CLI** | ✅ 6 hunts shipped | ❌ | ⚠️ UI-driven | ⚠️ UI-driven |
| **Verify-it-works script** | ✅ attack-sim + verify-detect | ❌ | ❌ | ❌ |
| **MITRE ATT&CK tags on rules** | ✅ inline | ✅ | ✅ | ✅ |
| **Grafana dashboard JSON** | ✅ in-repo | ❌ | n/a | n/a |
| **Self-hosted** | ✅ | ✅ | ❌ SaaS only | ❌ SaaS only |

Not competing with Sysdig/Datadog — they win on scale and ML enrichment. But for "a team that wants real runtime detection without a 5-figure annual bill," this stack is the right shape.

---

## Quickstart

### Prereqs

- A running Kubernetes cluster (kind, EKS, anything that supports DaemonSets + eBPF). On kind, kernel ≥ 5.8.
- `kubectl`, `helm`, `go 1.22+`.

### Install the stack (~5 min)

```bash
git clone https://github.com/mohidev-tech/runtime-detect
cd runtime-detect

./scripts/bootstrap.sh    # Loki + Falcosidekick + Falco + Grafana dashboard
```

### Trip the rules + verify

```bash
./scripts/attack-sim.sh   # exec into a pod and do bad-but-harmless things
./scripts/verify-detect.sh # exits 0 only when every expected hunt fired
```

### Ad-hoc hunt run

```bash
cd tools/hunt
go run ./cmd/hunt list                       # show every hunt
go run ./cmd/hunt run --since 1h             # run all over last hour
go run ./cmd/hunt run --id HUNT-003          # run one
go run ./cmd/hunt run --format json > out.json
```

### Open Grafana

```bash
kubectl -n monitoring port-forward svc/kps-grafana 3000:80
# admin / admin → "runtime-detect — Falco events" dashboard
```

---

## Repo layout

```
deploy/
  falco/
    values.yaml             Helm values: eBPF driver, JSON output, http→sidekick
    custom-rules.yaml       Our 5 hand-picked K8s rules (MITRE-tagged)
    falcosidekick.yaml      Event router: → Loki always, → Slack on critical
  loki/values.yaml          Single-binary Loki, filesystem storage
  grafana/dashboards/
    runtime-events.json     4 stat panels + timeseries + top rules + log feed
tools/hunt/                 Go CLI; queries Loki using detection-as-code definitions
  cmd/hunt/main.go          list / run subcommands
  internal/loki/client.go   Minimal Loki HTTP client (no external deps)
  internal/hunts/hunts.go   6 hunts as Go structs — add a hunt = one PR
scripts/
  bootstrap.sh              Install everything in order
  attack-sim.sh             Trip every custom rule (negative test for the pipeline)
  verify-detect.sh          Assert every trip landed in Loki within 10 min
docs/adr/                   architecture decision records
```

---

## The five Falco rules

| Rule | Trigger | MITRE |
|---|---|---|
| **Shell spawned in app container** | `sh`/`bash`/`ash`/`fish` proc starts inside a container in `app`/`default` | T1059 (Execution) |
| **Write to K8s service-account directory** | Open-for-write under `/var/run/secrets/kubernetes.io` or `/etc/kubernetes` | T1098 (Account Manipulation) |
| **Sensitive file read inside container** | Open-for-read on `/etc/shadow` or `/etc/sudoers` | T1003 (OS Credential Dumping) |
| **Outbound DNS to suspicious domain** | Container resolves/dials anything in the `suspicious_domains` IOC list | TA0011 (Command & Control) |
| **Mount inside container** | `mount` syscall in a container (escape precursor) | T1611 (Escape to Host) |

Custom rules are loaded **alongside** Falco's upstream rule set — we don't replace it. Upstream catches broad patterns; ours add the K8s-specific signals.

---

## Design choices

| Choice | Why |
|---|---|
| **Falco eBPF driver, not the kernel module** | eBPF doesn't need privileged kernel-module install. Works on most modern distros (kernel ≥ 5.8). Lower deployment friction. |
| **Falcosidekick as the router, not raw HTTP output** | Sidekick has built-in fan-out to ~50 backends (Loki, Slack, S3, etc.). Adding a SIEM later is a values.yaml change, not a code change. |
| **Loki, not Elasticsearch** | Loki's "index labels, not content" model matches Falco's structured JSON output. Cheaper at scale, simpler to operate, native Grafana integration. |
| **Hunts as Go code, not YAML** | A hunt is a query + a threshold + tags. Code beats YAML for "review what changes when someone adds a hunt." The Go file IS the source of truth. |
| **Attack-sim + verify-detect as a pair** | "Falco is installed" ≠ "Falco is detecting." The only way to keep the pipeline honest is to trip it on purpose and confirm the events arrive. |

---

## Limitations — documented, not hidden

- **IOC list is curated, not threat-feed-driven.** The `suspicious_domains` list in `custom-rules.yaml` is three placeholders. In a real deployment, plug in the `falco-plugins-http` plugin or pre-process a TI feed into a ConfigMap.
- **No alert correlation.** Each hunt is independent. A real SOC would tie "shell spawned" + "sensitive file read" from the same pod within 5 minutes into one incident. That belongs in a separate correlation layer (e.g. Falco's reaction-engine, or a downstream SIEM).
- **Loki is single-binary, single-replica.** Fine for the lab; for production, deploy the scalable read/write/backend split with object storage.
- **`attack-sim` requires the target pod to have a shell available** (`alpine`). The whole point is the rules trip; a distroless app pod wouldn't be a useful test target since it can't spawn a shell.

---

## How this slots into the portfolio

| Layer | Repo | Job |
|---|---|---|
| **Build** | [secure-supply-chain](https://github.com/mohidev-tech/secure-supply-chain) | Sign + SBOM-attest images |
| **Admission** | [devsecops-platform](https://github.com/mohidev-tech/devsecops-platform) + [zero-trust-k8s](https://github.com/mohidev-tech/zero-trust-k8s) | Refuse to admit unsigned/unsafe pods |
| **Runtime** | **runtime-detect** *(this repo)* | Catch what slipped past admission |
| **IaC scan** | [cspm-scanner](https://github.com/mohidev-tech/cspm-scanner) | Catch what would have built the cluster wrong in the first place |

This is the **runtime layer** — when build-time, admission-time, and IaC-time checks all let something through, this is what catches it actively.

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
