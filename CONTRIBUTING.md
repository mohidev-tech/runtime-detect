# Contributing to runtime-detect

PRs welcome. The most valuable contributions are:

- New Falco rules (with a corresponding attack-sim step + hunt).
- New hunts that catch a real pattern the existing rules miss.
- Stronger verify-detect: more precise assertions, faster feedback.

## Local development loop

```bash
git clone https://github.com/mohidev-tech/runtime-detect
cd runtime-detect

./scripts/bootstrap.sh        # one-time install on your kind cluster
./scripts/attack-sim.sh       # trip every rule
./scripts/verify-detect.sh    # assert every trip landed in Loki

# Iterate on the hunt CLI
cd tools/hunt
go test ./...
go run ./cmd/hunt run --since 30m
```

## Adding a Falco rule + matching hunt

A new detection capability is three small PRs' worth of work; do them in one PR per capability:

1. **Add the Falco rule** in `deploy/falco/custom-rules.yaml`. Include MITRE tags.
2. **Trip it** in `scripts/attack-sim.sh` — a new step that performs the action your rule should catch.
3. **Hunt it** in `tools/hunt/internal/hunts/hunts.go` — add a `Hunt{ID:..., LogQL:..., ...}` entry.
4. **Update the README's "five rules" table** to be six.

Reload Falco for the new rule to take effect:

```bash
kubectl -n runtime-detect rollout restart ds/falco
```

Re-run attack-sim + verify-detect to confirm the new path works end-to-end.

## Adding a hunt (without a new Falco rule)

Sometimes you want to surface a pattern in existing Falco events:

```go
{
  ID:    "HUNT-007",
  Title: "Container runtime config tampering",
  Description: "Writes under /var/lib/docker or /var/lib/containerd. Should " +
    "never happen from inside an unprivileged container.",
  LogQL:   `{app="falco", priority="Warning"} |~ "(?i)write to /var/lib/(docker|containerd)"`,
  MinHits: 1,
  Tags:    []string{"persistence"},
}
```

## PR checklist

- [ ] `go test ./...` passes in `tools/hunt`.
- [ ] If you added a Falco rule: `attack-sim.sh` has a step that trips it.
- [ ] If you added a hunt: `MinHits` is justified (default 1, higher only with a documented reason).
- [ ] If you changed LogQL: the existing dashboard panels still work (port-forward Grafana and look).
- [ ] MITRE ATT&CK tags are present on new rules where applicable.

## What "good" looks like

- **Every rule fires deliberately in attack-sim.** A rule that no one knows how to trip is a rule no one knows is broken.
- **Every hunt has a description that explains the investigation step.** "What does an analyst do when this fires?" should be answerable from the description alone.
- **No false-positive-friendly defaults.** `MinHits` defaults to 1 — make repeated-hit thresholds explicit and explain why.

## License

By submitting a PR you agree the contribution is Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
