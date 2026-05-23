#!/usr/bin/env bash
# Deliberately trip every custom Falco rule so verify-detect.sh can confirm
# the pipeline (Falco -> falcosidekick -> Loki) is working end-to-end.
#
#   ./scripts/attack-sim.sh
#
# Each action is something a real attacker (or a curious operator) would
# do — but harmless in this lab cluster because the pods we exec into
# only exist for this purpose. Don't run against production.
set -euo pipefail

NS="${NS:-app}"
TARGET_POD="${TARGET_POD:-attack-target}"

echo "==> Setting up target pod in $NS"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# A pod with a shell available (using alpine), running as non-root so it
# still passes Gatekeeper if it's installed. The point is to exec in and
# do things — not to bypass anything at admission.
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $TARGET_POD
  namespace: $NS
  labels: { app.kubernetes.io/name: attack-target, owner: lab }
spec:
  containers:
    - name: target
      image: alpine:3.20
      command: ["sleep", "3600"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        readOnlyRootFilesystem: false   # we WANT to be writable for the test
      readinessProbe: { exec: { command: ["true"] } }
      livenessProbe:  { exec: { command: ["true"] } }
EOF
kubectl -n "$NS" wait --for=condition=ready pod/"$TARGET_POD" --timeout=60s

# Helper to run a command in the target pod.
in_pod() { kubectl -n "$NS" exec "$TARGET_POD" -- "$@"; }

echo "==> [1] spawn shell in app container (HUNT-001)"
in_pod sh -c 'echo "I am a shell, hello" && true' || true
sleep 1

echo "==> [2] write to /var/run/secrets/kubernetes.io (HUNT-002)"
in_pod sh -c 'echo bad > /var/run/secrets/kubernetes.io/zzz-injected 2>/dev/null || true'
sleep 1

echo "==> [3] read /etc/shadow (HUNT-003)"
in_pod sh -c 'cat /etc/shadow > /dev/null 2>&1 || true'
sleep 1

echo "==> [4] DNS lookup of evil.attacker.invalid (HUNT-004)"
in_pod sh -c 'getent hosts evil.attacker.invalid || nslookup evil.attacker.invalid || true' 2>/dev/null
sleep 1

echo "==> [5] mount inside container (HUNT-005)"
# This will fail (alpine isn't privileged), but the attempted syscall still
# fires the rule — which is the point. Falco detects the SYSCALL, not the
# successful state change.
in_pod sh -c 'mount -t tmpfs none /mnt 2>&1 || true'
sleep 1

echo ""
echo "==> Wait ~10s for events to flow through Falco -> sidekick -> Loki ..."
sleep 10

echo "==> Done. Now run: ./scripts/verify-detect.sh"
