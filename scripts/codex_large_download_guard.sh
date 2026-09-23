#!/usr/bin/env bash
set -euo pipefail

# Server-side guard for downloads larger than 1 GiB.  Route helpers and
# binaries are injected by the server environment; no private endpoint or
# home directory is assumed by the open-source script.
threshold_bytes=$((1024 * 1024 * 1024))
route="racknerd"
expected_egress=""
expected_bytes=""
url=""
output=""
sha256=""
connections=4
execute=false
route_helper=${LAD_RACKNERD_ROUTE_BIN:-${HOME}/.local/bin/codex-racknerd-route}
aria2_bin=${LAD_ARIA2_BIN:-/usr/bin/aria2c}

usage() {
  printf '%s\n' \
    'Usage: codex-large-download [options]' \
    '  --route racknerd|direct       Transfer route (default: racknerd)' \
    '  --expected-egress IP          Required when --route direct is used' \
    '  --expected-bytes BYTES        Exact expected size; must exceed 1 GiB' \
    '  --url URL                     Server-origin download URL' \
    '  --output ABSOLUTE_PATH        Server-local destination' \
    '  --sha256 HEX                  Optional expected SHA-256' \
    '  --connections 1..8            Parallel ranges for one object (default: 4)' \
    '  --execute                     Execute after the mandatory plan invocation'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --route) route=${2:-}; shift 2 ;;
    --expected-egress) expected_egress=${2:-}; shift 2 ;;
    --expected-bytes) expected_bytes=${2:-}; shift 2 ;;
    --url) url=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    --sha256) sha256=${2:-}; shift 2 ;;
    --connections) connections=${2:-}; shift 2 ;;
    --execute) execute=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

[[ "$route" == "racknerd" || "$route" == "direct" ]] || {
  echo "--route must be racknerd or direct" >&2
  exit 64
}
[[ "$expected_bytes" =~ ^[0-9]+$ ]] || {
  echo "--expected-bytes is required and must be an integer" >&2
  exit 64
}
[[ -n "$url" && -n "$output" ]] || {
  echo "--url and --output are required" >&2
  exit 64
}
[[ "$output" == /* ]] || {
  echo "--output must be an absolute server-local path" >&2
  exit 64
}
[[ "$connections" =~ ^[1-8]$ ]] || {
  echo "--connections must be between 1 and 8" >&2
  exit 64
}
if [[ -n "$sha256" && ! "$sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "--sha256 must contain exactly 64 hexadecimal characters" >&2
  exit 64
fi
if (( expected_bytes <= threshold_bytes )); then
  echo "this guard is for downloads larger than 1 GiB" >&2
  exit 64
fi
[[ -d "$(dirname "$output")" ]] || {
  echo "output directory does not exist" >&2
  exit 66
}

clear_proxy_env=(
  env
  -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY
  -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY
)

verified_egress=""
verify_route() {
  if [[ "$route" == "racknerd" ]]; then
    local result
    [[ -x "$route_helper" ]] || {
      echo "RackNerd route helper is unavailable: $route_helper" >&2
      exit 69
    }
    result=$("$route_helper" verify)
    verified_egress=${result##*egress=}
    [[ -n "$verified_egress" ]] || {
      echo "RackNerd verification returned no egress identity" >&2
      exit 69
    }
    return
  fi

  [[ -n "$expected_egress" ]] || {
    echo "--expected-egress is required for the direct route" >&2
    exit 64
  }
  local endpoint observed
  for endpoint in \
    https://ifconfig.me/ip \
    https://icanhazip.com \
    https://checkip.amazonaws.com; do
    observed=$("${clear_proxy_env[@]}" curl -4fsS --max-time 12 "$endpoint" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "$observed" ]]; then
      verified_egress=$observed
      break
    fi
  done
  [[ -n "$verified_egress" ]] || {
    echo "direct route egress could not be observed" >&2
    exit 69
  }
  [[ "$verified_egress" == "$expected_egress" ]] || {
    echo "direct egress mismatch: expected=$expected_egress observed=$verified_egress" >&2
    exit 69
  }
}

verify_route

if [[ "$execute" != true ]]; then
  printf 'plan route=%s egress=%s expected_bytes=%s output=%s connections=%s\n' \
    "$route" "$verified_egress" "$expected_bytes" "$output" "$connections"
  echo "rerun with --execute after confirming the target"
  exit 0
fi

output_dir=$(dirname "$output")
output_name=$(basename "$output")
aria2_args=(
  --continue=true
  --allow-overwrite=true
  --auto-file-renaming=false
  --file-allocation=none
  --max-tries=0
  --retry-wait=10
  --connect-timeout=30
  --timeout=120
  --max-connection-per-server="$connections"
  --split="$connections"
  --min-split-size=16M
  --dir="$output_dir"
  --out="$output_name"
)

if [[ ! -x "$aria2_bin" ]]; then
  echo "aria2c is unavailable: $aria2_bin" >&2
  exit 69
fi
if [[ "$route" == "racknerd" ]]; then
  racknerd_proxy=${LAD_RACKNERD_PROXY_URL:-}
  [[ -n "$racknerd_proxy" ]] || {
    echo "LAD_RACKNERD_PROXY_URL must be set for the racknerd route" >&2
    exit 69
  }
  "$aria2_bin" --all-proxy="$racknerd_proxy" "${aria2_args[@]}" "$url"
else
  "${clear_proxy_env[@]}" "$aria2_bin" --all-proxy= "${aria2_args[@]}" "$url"
fi

verify_route
actual_bytes=$(stat -c '%s' "$output")
if [[ "$actual_bytes" != "$expected_bytes" ]]; then
  echo "byte count mismatch: expected=$expected_bytes actual=$actual_bytes" >&2
  exit 1
fi
actual_sha256=""
if [[ -n "$sha256" ]]; then
  actual_sha256=$(sha256sum "$output" | awk '{print $1}')
  [[ "${actual_sha256,,}" == "${sha256,,}" ]] || {
    echo "SHA-256 mismatch: expected=${sha256,,} actual=${actual_sha256,,}" >&2
    exit 1
  }
fi
printf 'download_verified route=%s egress=%s bytes=%s sha256=%s output=%s\n' \
  "$route" "$verified_egress" "$actual_bytes" "${actual_sha256:-not-requested}" "$output"
