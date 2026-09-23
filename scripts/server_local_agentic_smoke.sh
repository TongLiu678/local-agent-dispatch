#!/usr/bin/env bash
set -euo pipefail

root=${LOCAL_AGENT_DISPATCH_ROOT:-${LAD_PROJECT_ROOT:-${HOME}/.local/share/local-agent-dispatch}}
fixture=${1:-$root/smoke-fixture}
host_id=${LOCAL_AGENT_DISPATCH_HOST_ID:-${2:-unknown_remote}}
endpoint=${LOCAL_AGENT_DISPATCH_ENDPOINT:-http://127.0.0.1:8000/v1}
model=${LOCAL_AGENT_DISPATCH_MODEL:-qwen2.5-coder-14b-awq}
aider_venv=$root/venvs/aider
secure_python_index=https://mirrors.aliyun.com/pypi/simple
uv_bin=${LAD_UV_BIN:-${HOME}/.local/bin/uv}
python_bin=${LAD_PYTHON_BIN:-$(command -v python3)}
logs=$root/logs
run_dir=$root/run
run_id=$(date -u +%Y%m%dT%H%M%SZ)
workspace=$root/smoke/qwen25-awq-$run_id
log=$logs/qwen25-awq-agentic-smoke-$run_id.log
result=$workspace/agentic-smoke.json

mkdir -p "$workspace" "$logs" "$run_dir" "$root/venvs"
[[ -f "$fixture/buggy_math.py" && -f "$fixture/test_buggy_math.py" && -f "$fixture/TASK.md" ]] || {
  echo "agentic smoke fixture is incomplete: $fixture" >&2
  exit 66
}
cp -p "$fixture/buggy_math.py" "$fixture/test_buggy_math.py" "$fixture/TASK.md" "$workspace/"

curl -fsS --max-time 10 "$endpoint/models" >/dev/null
if [[ ! -x "$uv_bin" ]]; then
  echo "uv is unavailable; vLLM deployment must finish first" >&2
  exit 69
fi
if [[ ! -x "$aider_venv/bin/python" ]]; then
  UV_DEFAULT_INDEX="$secure_python_index" \
    "$uv_bin" venv --python "$python_bin" --seed "$aider_venv"
fi
if [[ ! -x "$aider_venv/bin/aider" ]]; then
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    UV_DEFAULT_INDEX="$secure_python_index" \
    "$uv_bin" pip install --python "$aider_venv/bin/python" aider-chat
fi

cd "$workspace"
git init -q
git config user.name local-agent-dispatch-smoke
git config user.email local-agent-dispatch-smoke@invalid
git add buggy_math.py test_buggy_math.py TASK.md
git commit -qm baseline

if "$python_bin" -m unittest -v >"$logs/qwen25-awq-baseline-$run_id.log" 2>&1; then
  echo "smoke fixture unexpectedly passed before the agent ran" >&2
  exit 1
fi

set +e
env \
  OPENAI_API_BASE="$endpoint" \
  OPENAI_API_KEY=server-local-no-external-key \
  timeout 600 "$aider_venv/bin/aider" \
    --model "openai/$model" \
    --edit-format whole \
    --yes-always \
    --no-auto-commits \
    --no-gitignore \
    --no-show-model-warnings \
    --map-tokens 0 \
    --no-stream \
    --test-cmd "$python_bin -m unittest -v" \
    --auto-test \
    --message-file TASK.md \
    buggy_math.py test_buggy_math.py >"$log" 2>&1
aider_rc=$?
set -e

if (( aider_rc != 0 )); then
  echo "Aider smoke failed with exit $aider_rc; see $log" >&2
  exit "$aider_rc"
fi
"$python_bin" -m unittest -v >>"$log" 2>&1
if git diff --quiet -- buggy_math.py; then
  echo "Aider returned success without changing buggy_math.py" >&2
  exit 1
fi

artifact_sha=$(sha256sum buggy_math.py | awk '{print $1}')
completed_at=$(date -u +%FT%TZ)
printf '%s\n' \
  '{' \
  '  "status": "passed",' \
  "  \"completed_at_utc\": \"$completed_at\"," \
  "  \"host_id\": \"$host_id\"," \
  "  \"model\": \"$model\"," \
  "  \"endpoint\": \"$endpoint\"," \
  '  "agent": "aider",' \
  '  "validation": "python3 -m unittest -v",' \
  '  "max_difficulty": 2,' \
  '  "requires_provider_review": true,' \
  "  \"workspace\": \"$workspace\"," \
  "  \"log\": \"$log\"," \
  "  \"artifact_sha256\": \"$artifact_sha\"" \
  '}' >"$result"
cp -p "$result" "$run_dir/agentic-smoke.json"
printf 'agentic_smoke_passed model=%s workspace=%s log=%s sha256=%s\n' \
  "$model" "$workspace" "$log" "$artifact_sha"
