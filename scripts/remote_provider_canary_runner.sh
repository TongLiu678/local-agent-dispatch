#!/usr/bin/env bash
# Run exact provider canaries on a server after authentication.
# Fail closed: never substitute a provider, route, or model.
set -u
umask 077

BASE="${LAD_PROJECT_ROOT:-/srv/local-agent-dispatch}"
SRC="$BASE/source"
OUT="${LAD_PROVIDER_CANARY_OUT:-$BASE/control/provider-canary}"
ROUTE_ROOT="$BASE/control/racknerd"
EXPECTED_EGRESS="${LAD_EXPECTED_EGRESS:-}"
WAIT_SECONDS="${LAD_PROVIDER_CANARY_WAIT_SECONDS:-1800}"
EXPECTED_ANTIGRAVITY_MODEL="${LAD_ANTIGRAVITY_MODEL:-gemini-3.6-flash-high}"
ANTIGRAVITY_BIN="${LAD_ANTIGRAVITY_BIN:-agy}"

mkdir -p "$OUT"
if [ -z "$EXPECTED_EGRESS" ]; then
  printf '%s\n' '{"schema_version":"provider-canary-runner.v1","state":"expected_egress_missing"}' > "$OUT/status.json"
  exit 3
fi
export PATH="$BASE/tools/node-v24.20.0-linux-x64/bin:$BASE/tools/npm-global/bin:$BASE/tools/bin:$PATH"
export CODEX_HOME="${CODEX_HOME:-$BASE/control/codex-home}"
ANTIGRAVITY_HOME="${LAD_ANTIGRAVITY_HOME:-$BASE/control/antigravity-home}"
mkdir -p "$CODEX_HOME" "$ANTIGRAVITY_HOME" "$ANTIGRAVITY_HOME/.config"
# Keep Antigravity's file-based OAuth store separate from both the server's
# default root account and any other project running on the same host.  Do not
# export HOME globally: Codex is scoped by CODEX_HOME, while this wrapper
# intentionally scopes only Antigravity invocations.  An env argv is used
# instead of a shell function because `timeout` cannot execute shell functions.
agy_env=(env "HOME=$ANTIGRAVITY_HOME" "XDG_CONFIG_HOME=$ANTIGRAVITY_HOME/.config")
if [ ! -r "$ROUTE_ROOT/ports.env" ]; then
  printf '%s\n' '{"schema_version":"provider-canary-runner.v1","state":"route_config_missing"}' > "$OUT/status.json"
  exit 3
fi
. "$ROUTE_ROOT/ports.env"
export HTTP_PROXY="http://127.0.0.1:${http_port}"
export HTTPS_PROXY="$HTTP_PROXY"
export ALL_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"
export all_proxy="$HTTP_PROXY"
export NO_PROXY="127.0.0.1,localhost"

route_egress="$(env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy curl -fsS --proxy "$HTTP_PROXY" --connect-timeout 8 --max-time 15 https://ifconfig.me/ip 2>/dev/null || true)"
if [ "$route_egress" != "$EXPECTED_EGRESS" ]; then
  printf '{"schema_version":"provider-canary-runner.v1","state":"route_unverified","expected_egress":"%s","observed_egress":"%s"}\n' "$EXPECTED_EGRESS" "$route_egress" > "$OUT/status.json"
  exit 3
fi

deadline=$(( $(date +%s) + WAIT_SECONDS ))
printf '{"schema_version":"provider-canary-runner.v1","state":"waiting","host":"%s","route_egress":"%s"}\n' "$(hostname)" "$route_egress" > "$OUT/status.json"
codex_authenticated=false
antigravity_model=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  if codex login status >"$OUT/codex-status.txt" 2>&1; then codex_authenticated=true; else codex_authenticated=false; fi
  timeout 30s "${agy_env[@]}" "$ANTIGRAVITY_BIN" models >"$OUT/agy-models.txt" 2>&1 || true
  if grep -Fq "$EXPECTED_ANTIGRAVITY_MODEL" "$OUT/agy-models.txt"; then
    antigravity_model="$EXPECTED_ANTIGRAVITY_MODEL"
  else
    antigravity_model=""
  fi
  if [ "$codex_authenticated" = true ] && [ -n "$antigravity_model" ]; then break; fi
  printf '{"schema_version":"provider-canary-runner.v1","state":"waiting","host":"%s","route_egress":"%s","codex_authenticated":%s,"antigravity_model_found":%s}\n' "$(hostname)" "$route_egress" "$codex_authenticated" "$([ -n "$antigravity_model" ] && echo true || echo false)" > "$OUT/status.json"
  sleep 20
done

if [ "$codex_authenticated" != true ] || [ -z "$antigravity_model" ]; then
  printf '{"schema_version":"provider-canary-runner.v1","state":"auth_timeout","host":"%s","route_egress":"%s","codex_authenticated":%s,"antigravity_model_found":%s}\n' "$(hostname)" "$route_egress" "$codex_authenticated" "$([ -n "$antigravity_model" ] && echo true || echo false)" > "$OUT/status.json"
  exit 2
fi

spark_log="$OUT/spark.jsonl"
spark_stderr="$OUT/spark.stderr"
spark_last="$OUT/spark-last.txt"
spark_prompt='Read the repository instructions and report exactly three short facts: the current branch commit if available, whether provider-free tests are documented, and one remaining real-provider gate. Do not edit files.'
set +e
printf '%s\n' "$spark_prompt" | codex exec -m gpt-5.3-codex-spark -c 'model_reasoning_effort="xhigh"' --sandbox read-only --cd "$SRC" --ephemeral --json --output-last-message "$spark_last" >"$spark_log" 2>"$spark_stderr"
spark_rc=$?
set -e

agy_log="$OUT/antigravity.json"
agy_stderr="$OUT/antigravity.stderr"
agy_prompt='Read the repository instructions and report exactly three short facts: the current branch commit if available, whether provider-free tests are documented, and one remaining real-provider gate. Do not edit files.'
set +e
"${agy_env[@]}" "$ANTIGRAVITY_BIN" -p "$agy_prompt" --model "$antigravity_model" --effort high --output-format json --print-timeout 10m >"$agy_log" 2>"$agy_stderr"
agy_rc=$?
set -e

python3 - "$OUT" "$antigravity_model" "$spark_rc" "$agy_rc" <<'PY'
import hashlib
import json
import pathlib
import socket
import sys
from datetime import datetime, timezone
out = pathlib.Path(sys.argv[1])
agy_model = sys.argv[2]
spark_rc, agy_rc = int(sys.argv[3]), int(sys.argv[4])
spark_last = out / "spark-last.txt"
agy_json = out / "antigravity.json"
agy_success = False
try:
    agy_success = json.loads(agy_json.read_text()).get("status") == "SUCCESS"
except (OSError, ValueError):
    pass
payload = {
    "schema_version": "provider-canary-receipt.v1",
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "host": socket.gethostname(),
    "spark": {
        "model": "gpt-5.3-codex-spark",
        "reasoning_effort": "xhigh",
        "exit_code": spark_rc,
        "response_nonempty": spark_last.is_file() and spark_last.stat().st_size > 0,
        "log": str(out / "spark.jsonl"),
        "stderr": str(out / "spark.stderr"),
        "sha256": hashlib.sha256((out / "spark.jsonl").read_bytes()).hexdigest(),
    },
    "antigravity": {
        "model": agy_model,
        "effort": "high",
        "exit_code": agy_rc,
        "status_success": agy_success,
        "log": str(agy_json),
        "stderr": str(out / "antigravity.stderr"),
        "sha256": hashlib.sha256(agy_json.read_bytes()).hexdigest(),
    },
}
payload["success"] = (
    payload["spark"]["exit_code"] == 0
    and payload["spark"]["response_nonempty"]
    and payload["antigravity"]["exit_code"] == 0
    and payload["antigravity"]["status_success"]
)
(out / "receipt.json").write_text(json.dumps(payload, sort_keys=True) + "\n")
PY

if python3 - "$OUT/receipt.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    raise SystemExit(0 if json.load(f)["success"] else 1)
PY
then
  printf '{"schema_version":"provider-canary-runner.v1","state":"success","host":"%s","route_egress":"%s","spark_model":"gpt-5.3-codex-spark","antigravity_model":"%s"}\n' "$(hostname)" "$route_egress" "$antigravity_model" > "$OUT/status.json"
  exit 0
fi
printf '{"schema_version":"provider-canary-runner.v1","state":"failed","host":"%s","route_egress":"%s","spark_model":"gpt-5.3-codex-spark","antigravity_model":"%s","spark_exit_code":%s,"antigravity_exit_code":%s}\n' "$(hostname)" "$route_egress" "$antigravity_model" "$spark_rc" "$agy_rc" > "$OUT/status.json"
exit 1
