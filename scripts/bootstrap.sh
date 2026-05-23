#!/usr/bin/env bash
# Install the full runtime-detect stack on an existing kind/EKS cluster.
#
#   ./scripts/bootstrap.sh
#
# Order:
#   1. namespace
#   2. Loki (single-binary)
#   3. Falcosidekick (HTTP receiver for Falco)
#   4. Falco (eBPF driver, custom rules, ships to falcosidekick)
#   5. Grafana datasource for Loki + dashboard sidecar import
set -euo pipefail

NS="runtime-detect"

helm repo add falcosecurity   https://falcosecurity.github.io/charts        2>/dev/null || true
helm repo add grafana         https://grafana.github.io/helm-charts          2>/dev/null || true
helm repo update

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Installing Loki"
helm upgrade --install loki grafana/loki \
  -n "$NS" -f deploy/loki/values.yaml \
  --wait --timeout 5m

echo "==> Installing Falcosidekick"
helm upgrade --install falcosidekick falcosecurity/falcosidekick \
  -n "$NS" -f deploy/falco/falcosidekick.yaml \
  --wait --timeout 3m

echo "==> Installing Falco"
helm upgrade --install falco falcosecurity/falco \
  -n "$NS" \
  -f deploy/falco/values.yaml \
  -f deploy/falco/custom-rules.yaml \
  --wait --timeout 5m

echo "==> Importing Grafana dashboard"
# Assumes kube-prometheus-stack from the flagship is installed in `monitoring`.
# If not, the sidecar isn't watching and you'll need to import manually.
kubectl -n monitoring create configmap runtime-detect-dashboard \
  --from-file=runtime-events.json=deploy/grafana/dashboards/runtime-events.json \
  --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null \
  || echo "  (skipped — no 'monitoring' namespace; install kube-prometheus-stack to auto-import)"
kubectl -n monitoring label configmap runtime-detect-dashboard grafana_dashboard=1 --overwrite 2>/dev/null || true

echo ""
echo "==> Done."
echo "    Loki:        kubectl -n $NS port-forward svc/loki 3100:3100"
echo "    Hunt CLI:    cd tools/hunt && go run ./cmd/hunt list"
echo "    Trip rules:  ./scripts/attack-sim.sh"
echo "    Verify:      ./scripts/verify-detect.sh"
