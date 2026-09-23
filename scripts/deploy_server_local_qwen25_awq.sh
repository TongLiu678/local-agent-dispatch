#!/usr/bin/env bash
set -euo pipefail

root=${LOCAL_AGENT_DISPATCH_ROOT:-${LAD_PROJECT_ROOT:-${LAD_STORAGE_ROOT:-${HOME}/.local/share/local-agent-dispatch}}}
model_dir=$root/models/Qwen2.5-Coder-14B-Instruct-AWQ
venv=$root/venvs/vllm
logs=$root/logs
state=$root/run
base=https://modelscope.cn/models/Qwen/Qwen2.5-Coder-14B-Instruct-AWQ/resolve/master
guard=${LAD_LARGE_DOWNLOAD_GUARD:-${HOME}/.local/bin/codex-large-download}
expected_egress=${LAD_EXPECTED_EGRESS:-}
uv_bin=${LAD_UV_BIN:-${HOME}/.local/bin/uv}
python_bin=${LAD_PYTHON_BIN:-$(command -v python3)}
served_model=qwen2.5-coder-14b-awq
main_log=$logs/qwen25-awq-deployment.log
secure_python_index=https://mirrors.aliyun.com/pypi/simple

[[ -n "$expected_egress" ]] || {
  echo "set LAD_EXPECTED_EGRESS after verifying the server egress identity" >&2
  exit 64
}
[[ -x "$guard" ]] || {
  echo "large-download guard is unavailable: $guard" >&2
  exit 69
}

mkdir -p "$model_dir" "$logs" "$state" "$root/venvs"
exec >>"$main_log" 2>&1
printf 'deployment_start_utc=%s\n' "$(date -u +%FT%TZ)"

free_bytes=$(df -PB1 "$root" | awk 'NR==2 {print $4}')
minimum_free=$((30 * 1024 * 1024 * 1024))
if (( free_bytes < minimum_free )); then
  echo "insufficient server disk: free=$free_bytes required=$minimum_free" >&2
  exit 70
fi

download_shard() {
  local name=$1 bytes=$2 sha=$3 log=$4
  local target=$model_dir/$name
  if [[ -f "$target" ]] && [[ "$(stat -c '%s' "$target")" == "$bytes" ]]; then
    local current_sha
    current_sha=$(sha256sum "$target" | awk '{print $1}')
    if [[ "$current_sha" == "$sha" ]]; then
      printf 'shard_reused name=%s bytes=%s sha256=%s\n' "$name" "$bytes" "$sha"
      return
    fi
  fi
  printf 'shard_start_utc=%s name=%s bytes=%s\n' "$(date -u +%FT%TZ)" "$name" "$bytes"
  "$guard" \
    --route direct \
    --expected-egress "$expected_egress" \
    --expected-bytes "$bytes" \
    --url "$base/$name" \
    --output "$target" \
    --sha256 "$sha" \
    --connections 4 \
    --execute >"$log" 2>&1
  printf 'shard_complete_utc=%s name=%s bytes=%s sha256=%s\n' \
    "$(date -u +%FT%TZ)" "$name" "$bytes" "$sha"
}

download_small() {
  local name=$1 bytes=$2 sha=$3
  local target=$model_dir/$name partial=$model_dir/$name.part
  if [[ -f "$target" ]] && [[ "$(stat -c '%s' "$target")" == "$bytes" ]]; then
    local current_sha
    current_sha=$(sha256sum "$target" | awk '{print $1}')
    if [[ "$current_sha" == "$sha" ]]; then
      printf 'small_reused name=%s bytes=%s sha256=%s\n' "$name" "$bytes" "$sha"
      return
    fi
  fi
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    curl -4fLsS --retry 5 --retry-delay 3 --max-time 600 \
      --output "$partial" "$base/$name"
  [[ "$(stat -c '%s' "$partial")" == "$bytes" ]] || {
    echo "byte count mismatch for $name" >&2
    exit 1
  }
  local current_sha
  current_sha=$(sha256sum "$partial" | awk '{print $1}')
  [[ "$current_sha" == "$sha" ]] || {
    echo "SHA-256 mismatch for $name" >&2
    exit 1
  }
  mv -f "$partial" "$target"
  printf 'small_complete name=%s bytes=%s sha256=%s\n' "$name" "$bytes" "$sha"
}

download_shard \
  model-00001-of-00003.safetensors 3988804408 \
  aacd6553a9ca787eb72d85761442afaaa02bc42d2ef677d9752060fb333aa0df \
  "$logs/qwen25-awq-shard-1.log" &
pid_one=$!
download_shard \
  model-00002-of-00003.safetensors 3968309440 \
  735a941a5b54c0ea645df2642314e187c4d590ac08cb01b5150bf09330bbf4bb \
  "$logs/qwen25-awq-shard-2.log" &
pid_two=$!

download_rc=0
wait "$pid_one" || download_rc=1
wait "$pid_two" || download_rc=1
if (( download_rc != 0 )); then
  echo "one of the first two model shards failed" >&2
  exit 1
fi

download_shard \
  model-00003-of-00003.safetensors 2023056736 \
  1c0174225b114921e13f0263c00d039f6609d6f25563fe100b13d92deb1a7b08 \
  "$logs/qwen25-awq-shard-3.log"

download_small .gitattributes 1561 17f71b31ccd4fd9ca414244ed3226bd6048b297fa211f242b1f3317e012d16d9
download_small config.json 841 af62852325fc708a05ee3fba8b7b0c53d352e2689870bff176098347fefa8ad0
download_small configuration.json 73 f888421726665e8a84b738eed42a64875aed79de8be7daade851ac8bf4c0cef9
download_small generation_config.json 243 ecb757011810ba01e0b9987c652f44108d10c2b13b791a035cca84d3537148b8
download_small LICENSE 11343 832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e
download_small merges.txt 1671839 599bab54075088774b1733fde865d5bd747cbcc7a547c5bc12610e874e26f5e3
download_small model.safetensors.index.json 107402 ffa9ad9dba1428d7e924ab03ab51b28865ddfad58b60f4d3d786f4f811a723cc
download_small README.md 2931 2f79c47077a32a80cf5492b2e6f72aa2c43548aed57f877d1cc16025951e10c8
download_small requirements.txt 17 8ba32a29324d6d18ff93f0d9c29903059b901d8a2591fb8b05e80807559841ef
download_small tokenizer.json 7031645 c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539
download_small tokenizer_config.json 7305 959e7f1d9a1b7641a6d6ce05ca97b75c7894fcb66cbe5a040406458fb1128ee4
download_small vocab.json 2776833 ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910
printf 'model_complete_utc=%s bytes=%s\n' "$(date -u +%FT%TZ)" "$(du -sb "$model_dir" | awk '{print $1}')"

if [[ ! -x "$uv_bin" ]]; then
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    PIP_INDEX_URL="$secure_python_index" \
    PIP_TRUSTED_HOST= \
    "$python_bin" -m pip install --user --upgrade uv
fi

if [[ ! -x "$venv/bin/python" ]]; then
  UV_DEFAULT_INDEX="$secure_python_index" \
    "$uv_bin" venv --python "$python_bin" --seed "$venv"
fi
if [[ ! -x "$venv/bin/vllm" ]]; then
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    UV_DEFAULT_INDEX="$secure_python_index" \
    UV_TORCH_BACKEND=auto \
    "$uv_bin" pip install --python "$venv/bin/python" vllm
fi
"$venv/bin/python" -c 'import torch,vllm; print("torch="+torch.__version__); print("cuda="+str(torch.version.cuda)); print("vllm="+vllm.__version__); print("gpu="+torch.cuda.get_device_name(0))'

if [[ -s "$state/vllm.pid" ]]; then
  old_pid=$(cat "$state/vllm.pid")
  if kill -0 "$old_pid" 2>/dev/null; then
    printf 'vllm_already_running pid=%s\n' "$old_pid"
    exit 0
  fi
fi

printf 'vllm_env VLLM_USE_FLASHINFER_SAMPLER=0 reason=flashinfer_sm120_jit_guard\n'
nohup env VLLM_USE_FLASHINFER_SAMPLER=0 "$venv/bin/vllm" serve "$model_dir" \
  --host 127.0.0.1 \
  --port 8000 \
  --served-model-name "$served_model" \
  --quantization awq \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.90 \
  >"$logs/vllm-qwen25-awq.log" 2>&1 </dev/null &
server_pid=$!
printf '%s\n' "$server_pid" >"$state/vllm.pid"
printf 'vllm_start_utc=%s pid=%s endpoint=http://127.0.0.1:8000/v1 model=%s\n' \
  "$(date -u +%FT%TZ)" "$server_pid" "$served_model"

for attempt in $(seq 1 60); do
  if curl -fsS --max-time 5 http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
    printf 'vllm_ready_utc=%s pid=%s\n' "$(date -u +%FT%TZ)" "$server_pid"
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "vLLM exited before becoming ready" >&2
    exit 1
  fi
  sleep 10
done

echo "vLLM did not become ready within 10 minutes" >&2
exit 1
