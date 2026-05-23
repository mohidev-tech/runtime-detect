# ADR 0001 — Hunts are Go code, not YAML

## Status
Accepted

## Context
A "hunt" — a runtime detection pattern expressed as a LogQL query plus metadata (severity threshold, MITRE tags, description) — could live in any of:

1. A YAML file under a `hunts/` directory.
2. A SQL/JSON DSL with custom parsers.
3. A Go struct in a registry, like `internal/hunts/hunts.go`.

We picked #3.

## Decision
Hunts are Go structs. Adding a hunt is a single `Hunt{...}` literal appended to the `All()` slice.

## Why
- **One source of truth.** Adding a hunt means editing one Go file; reviewing one hunt means reading one struct. No "metadata in YAML, query in another file, descriptions in the README."
- **Type-checked.** Forgot a `MinHits`? Compile error, not runtime surprise.
- **`go test`-friendly.** A hunt-validation test can iterate `hunts.All()` and assert e.g. "every hunt has at least one MITRE tag." That's awkward in pure YAML.
- **No DSL to maintain.** We don't need to parse our own format — LogQL goes into a string field, which is exactly what Loki wants anyway.

## What we give up
- **Non-Go users can't author hunts without rebuilding the binary.** This is the strongest argument for YAML — a SOC analyst with no Go background could edit `hunts.yaml`. For this portfolio repo's scope (one team, one binary, version-controlled), the trade-off is fine. A real organization with a dedicated SOC might justify the YAML loader.

## Consequences
- ✅ Adding a hunt is a one-line PR with full type safety.
- ✅ `hunt list` output is generated from the same source as the hunts themselves — they cannot drift.
- ⚠️ Hot-reload of hunts requires a rebuild. The hunt CLI is fast enough that this is fine; if it weren't, we'd embed the hunt slice into the binary at compile time and serve it via an HTTP endpoint.
