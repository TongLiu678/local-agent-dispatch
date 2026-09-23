#!/usr/bin/env bash
set -euo pipefail

root=${LOCAL_AGENT_DISPATCH_ROOT:-${LAD_PROJECT_ROOT:-${HOME}/.local/share/local-agent-dispatch}}
deployment_pid_file=${DEPLOYMENT_PID_FILE:-$root/run/vllm.pid}
smoke_script=${SMOKE_SCRIPT:-$root/server_local_agentic_smoke.sh}
fixture=${SMOKE_FIXTURE:-$root/smoke-fixture}
log=${SMOKE_SUPERVISOR_LOG:-$root/logs/qwen25-awq-smoke-supervisor.log}

exec >>"$log" 2>&1
printf 'smoke_supervisor_start_utc=%s\n' "$(date -u +%FT%TZ)"

for attempt in $(seq 1 540); do
  if curl -fsS --max-time 5 http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
    exec "$smoke_script" "$fixture"
  fi
  if [[ -s "$deployment_pid_file" ]]; then
    read -r deployment_pid < "$deployment_pid_file"
    if ! kill -0 "$deployment_pid" 2>/dev/null; then
      echo "deployment stopped before vLLM became ready" >&2
      exit 1
    fi
  fi
  sleep 10
done

echo "vLLM was not ready within 90 minutes" >&2
exit 1
