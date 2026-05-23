# ADR 0002 — Loki, not Elasticsearch, for the detection backend

## Status
Accepted

## Context
Falco's JSON events need to land somewhere queryable. The two dominant options in cloud-native land:

| | Loki | Elasticsearch / OpenSearch |
|---|---|---|
| **Storage model** | Index labels, store log content as-is | Index every field in inverted indices |
| **Cost at scale** | Linear with log volume; cheap | Disk + memory grows with cardinality |
| **Query language** | LogQL (PromQL-shaped) | DSL (JSON) or KQL |
| **Native Grafana integration** | First-class | First-class (panels), but UI experience is in Kibana |
| **Operational complexity** | Single-binary mode is trivial | Cluster + master nodes minimum |

## Decision
Loki, in single-binary mode for the lab.

## Why
- **Labels match Falco's shape.** Falcosidekick's Loki output assigns labels like `app=falco`, `priority=Critical`, `rule=<rule-name>`. That's exactly the shape Loki indexes well — low-cardinality fields as labels, message body as the log line.
- **Operationally trivial.** One pod, one PVC, one chart values file. Elasticsearch needs at minimum a 3-node setup to be safe.
- **PromQL-shaped query language.** Anyone fluent in Prometheus can write Loki queries on day one. That includes everyone running the flagship's kube-prometheus-stack.
- **Same Grafana, same dashboards.** The flagship already ships Grafana; runtime-detect's dashboard plugs into the existing instance.

## What we give up
- **No full-text search across log bodies.** Loki doesn't index the message content; only label values. If you want to find every event mentioning a specific filename, you have to filter by label first (e.g. `{rule="Sensitive file read"}`), then pipe through `|=` for the content match. For our hunts this is fine — each hunt knows which label to filter on first.
- **No ML-driven anomaly detection.** Elastic's ML jobs do this; Loki doesn't. Out of scope for this portfolio.

## Consequences
- ✅ Cheap, simple, fast to demo.
- ✅ Hunts live close to their data store (LogQL is the literal value of `Hunt.LogQL`).
- ⚠️ At >TB/day scale, the single-binary deployment runs out of headroom; swap to the read/write/backend split with S3/GCS storage. ADR 0003 will record that when we hit it.
