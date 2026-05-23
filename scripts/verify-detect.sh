#!/usr/bin/env bash
# Confirm every attack from attack-sim.sh was detected and landed in Loki
# within the lookback window. Exit code is non-zero if any hunt did not fire.
#
#   ./scripts/verify-detect.sh
#
# Equivalent to: cd tools/hunt && go run ./cmd/hunt run --since 10m
# but with a port-forward to Loki for environments where it's not exposed.
set -euo pipefail

NS="${NS:-runtime-detect}"

echo "==> Port-forwarding Loki"
kubectl -n "$NS" port-forward svc/loki 13100:3100 >/tmp/loki-pf.log 2>&1 &
PF=$!
# Single-quote so $PF expands at trap-fire time (shellcheck SC2064).
trap 'kill "$PF" 2>/dev/null || true' EXIT
sleep 3

echo "==> Running hunts (last 10m)"
( cd tools/hunt && LOKI_URL=http://localhost:13100 go run ./cmd/hunt run --since 10m )
rc=$?

if [ $rc -eq 0 ]; then
  echo ""
  echo "WARN: every hunt was clean. If you ran attack-sim.sh recently,"
  echo "      this might mean Falco isn't seeing those syscalls (driver"
  echo "      issue) OR falcosidekick isn't reaching Loki. Investigate:"
  echo "        kubectl -n $NS logs ds/falco -c falco --tail=50"
  echo "        kubectl -n $NS logs deploy/falcosidekick --tail=20"
  exit 1
fi

# `hunt run --fail-on-hit` returns 1 when hunts fire — which here is what
# we WANT (we just attacked, the hunts SHOULD fire).
echo ""
echo "==> Detections present — Falco -> falcosidekick -> Loki -> hunt is working."
exit 0
