# Security policy

This is a **runtime detection lab**. The threat model is: someone clones it, runs it in their cluster, and trusts that the detections are real. If a detection silently misses what it claims to catch, that's a security issue against this repo even though no service is "deployed."

## Reporting a vulnerability

→ [Report a vulnerability](https://github.com/mohidev-tech/runtime-detect/security/advisories/new)

Please include:

- Which rule or hunt is affected.
- A reproducer: an action that *should* have tripped the rule but didn't, OR an action the rule fires on that's actually benign.
- The Falco version and driver type (eBPF vs kernel module) you observed it on.

I aim to acknowledge within **72 hours**.

## Verify the pipeline yourself

The most important verification is end-to-end:

```bash
./scripts/attack-sim.sh
./scripts/verify-detect.sh   # exit 0 only when every expected hunt fired
```

If verify-detect ever exits 0 while a known attack action didn't show up in Loki, **that's a security bug.** The pipeline silently dropping events is the failure mode that matters most.

## Known design caveats — not vulnerabilities

| Caveat | Why | Where |
|---|---|---|
| **Falco uses eBPF, not kernel module** | Lower install friction; works on most cloud-managed nodes. Some legacy kernels (<5.8) won't run it — they need the kernel module. | [`deploy/falco/values.yaml`](deploy/falco/values.yaml) |
| **Loki single-binary, single-replica** | Lab-scale. For real volume, swap to read/write/backend split with object storage. | [ADR 0002](docs/adr/0002-loki-over-elasticsearch.md) |
| **`suspicious_domains` list has 3 placeholders** | The TI feed pattern is documented; productionizing requires plugging in an IOC source. | [`custom-rules.yaml`](deploy/falco/custom-rules.yaml) |
| **Attack-sim uses an alpine pod with a shell** | Other charts in this portfolio use distroless — but the WHOLE POINT of attack-sim is to spawn shells and read files, which requires a shell. The attack-sim pod is explicitly NOT distroless. | inline comment |
| **No alert correlation** | Each hunt is independent. Real SOCs need rules-of-rules; out of scope here. | README limitations |

## In scope for reports

- A rule that doesn't fire when its description says it should.
- A hunt's LogQL that returns no hits even though Loki contains matching events.
- A way to make Falco's eBPF driver miss a syscall the rule claims to catch.
- attack-sim steps that report "done" but don't actually perform the action.
- Privilege escalation via the hunt CLI's filesystem interactions (the CLI is read-only against the network, but if it can be tricked into writing somewhere unexpected, that's a bug).

## Out of scope

- Vulnerabilities in upstream Falco, Loki, falcosidekick. Report upstream.
- "Falco missed an attack we didn't write a rule for." Open a PR adding the rule + the attack-sim step + the hunt.
- Theoretical attacks without a reproducer.
