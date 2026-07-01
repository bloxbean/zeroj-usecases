#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${ROOT_DIR}/compose.demo.yml}"

usage() {
  cat <<'EOF'
Usage: ./demo.sh <usecase> [--run] [--clean-cache] [--stop] [--no-open] [--logs]

Usecases:
  proof-of-reserves
  voting
  airdrop
  dpp

Options:
  --run          Run the happy-path curl flow after the UI is healthy.
  --clean-cache  Remove this usecase's demo volume and regenerate setup from scratch.
  --stop         Stop the selected usecase container and exit.
  --no-open      Do not open the browser.
  --logs         Follow logs after startup/flow.

Examples:
  # Default provider is external Yaci DevKit on localhost:8080/10000.
  yaci-cli devkit start
  ./demo.sh voting
  ./demo.sh airdrop --run
  ./demo.sh proof-of-reserves --stop

  # Public Blockfrost-compatible endpoint. Fund DEMO_WALLET_MNEMONIC manually.
  DEMO_TOPUP_ENABLED=false \
  BLOCKFROST_BASE_URL=https://cardano-preprod.blockfrost.io/api/v0 \
  BLOCKFROST_PROJECT_ID=preprod... \
  CARDANO_NETWORK=preprod \
  PUBLISH_LOCAL_ZEROJ=false ./demo.sh dpp --run
EOF
}

if [ "$#" -lt 1 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  if [ "$#" -lt 1 ]; then
    exit 2
  fi
  exit 0
fi

USECASE="$1"
shift

RUN_FLOW=false
OPEN_UI=true
FOLLOW_LOGS=false
CLEAN_CACHE=false
STOP_DEMO=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run) RUN_FLOW=true ;;
    --clean-cache) CLEAN_CACHE=true ;;
    --stop) STOP_DEMO=true ;;
    --no-open) OPEN_UI=false ;;
    --logs) FOLLOW_LOGS=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

case "${USECASE}" in
  proof-of-reserves)
    PROFILE="proof-of-reserves"
    SERVICE="proof-of-reserves"
    VOLUME="proof-of-reserves-data"
    PORT="${PROOF_OF_RESERVES_PORT:-8089}"
    HEALTH="/api/reserves/status"
    ;;
  voting|private-voting)
    PROFILE="voting"
    SERVICE="voting"
    VOLUME="voting-data"
    PORT="${VOTING_PORT:-8086}"
    HEALTH="/api/status"
    ;;
  airdrop|personhood-airdrop)
    PROFILE="airdrop"
    SERVICE="airdrop"
    VOLUME="airdrop-data"
    PORT="${AIRDROP_PORT:-8083}"
    HEALTH="/api/airdrop/status"
    ;;
  dpp|digital-product-passport)
    PROFILE="dpp"
    SERVICE="dpp"
    VOLUME="dpp-data"
    PORT="${DPP_PORT:-8088}"
    HEALTH="/api/dpp/status"
    ;;
  *)
    echo "Unknown usecase: ${USECASE}" >&2
    usage
    exit 2
    ;;
esac

BASE_URL="http://localhost:${PORT}"
PROVIDER_BASE_URL="${BLOCKFROST_BASE_URL:-http://localhost:${YACI_STORE_API_PORT:-8080}/api/v1/}"
PROVIDER_HEALTH_URL="${PROVIDER_HEALTH_URL:-${YACI_HEALTH_URL:-${BF_HEALTH_URL:-${PROVIDER_BASE_URL%/}/epochs/latest}}}"
YACI_ADMIN_URL="${YACI_ADMIN_URL:-http://localhost:${YACI_CLUSTER_API_PORT:-10000}}"
DEMO_ADMIN_ADDRESS="${DEMO_ADMIN_ADDRESS:-addr_test1qryvgass5dsrf2kxl3vgfz76uhp83kv5lagzcp29tcana68ca5aqa6swlq6llfamln09tal7n5kvt4275ckwedpt4v7q48uhex}"
DEMO_ADMIN_ADA="${DEMO_ADMIN_ADA:-10000}"
DEMO_TOPUP_ENABLED="${DEMO_TOPUP_ENABLED:-true}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zeroj-demo}"
export COMPOSE_PROJECT_NAME

compose() {
  docker compose -f "${COMPOSE_FILE}" --profile "${PROFILE}" "$@"
}

wait_for_http() {
  url="$1"
  label="$2"
  attempts="${3:-180}"
  echo "Waiting for ${label} at ${url} ..."
  for _ in $(seq 1 "${attempts}"); do
    if curl_provider "${url}" >/dev/null 2>&1; then
      echo "${label} is ready."
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for ${label}." >&2
  return 1
}

curl_provider() {
  if [ -n "${BLOCKFROST_PROJECT_ID:-}" ]; then
    curl -fsS -H "project_id: ${BLOCKFROST_PROJECT_ID}" "$1"
  else
    curl -fsS "$1"
  fi
}

top_up_demo_wallet() {
  if [ "${DEMO_TOPUP_ENABLED}" != "true" ]; then
    echo "Skipping demo wallet top-up because DEMO_TOPUP_ENABLED=${DEMO_TOPUP_ENABLED}."
    return 0
  fi

  echo "Topping up demo wallet through ${YACI_ADMIN_URL} ..."
  curl -fsS -X POST "${YACI_ADMIN_URL}/local-cluster/api/addresses/topup" \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"${DEMO_ADMIN_ADDRESS}\",\"adaAmount\":${DEMO_ADMIN_ADA}}" >/dev/null
  echo "Demo wallet topped up: ${DEMO_ADMIN_ADDRESS}"
}

clean_demo_cache() {
  if [ "${CLEAN_CACHE}" != "true" ]; then
    return 0
  fi

  echo "Removing ${SERVICE} container and cache volume ${COMPOSE_PROJECT_NAME}_${VOLUME} ..."
  compose rm -sf "${SERVICE}" >/dev/null 2>&1 || true
  docker volume rm -f "${COMPOSE_PROJECT_NAME}_${VOLUME}" >/dev/null 2>&1 || true

  DEMO_CACHE_SEED_ENABLED=false
  export DEMO_CACHE_SEED_ENABLED
  echo "Committed demo cache seeding disabled for this run; setup will regenerate."
}

stop_demo() {
  echo "Stopping ${SERVICE} ..."
  compose stop "${SERVICE}" >/dev/null
  echo "Stopped ${SERVICE}."
}

post_json() {
  path="$1"
  body="$2"
  curl -fsS -X POST "${BASE_URL}${path}" \
    -H "Content-Type: application/json" \
    -d "${body}"
  printf '\n'
}

open_ui() {
  if [ "${OPEN_UI}" != "true" ]; then
    return 0
  fi
  if command -v open >/dev/null 2>&1; then
    open "${BASE_URL}"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${BASE_URL}" >/dev/null 2>&1 || true
  else
    echo "Open ${BASE_URL}"
  fi
}

run_flow() {
  case "${PROFILE}" in
    proof-of-reserves)
      post_json "/api/reserves/build-tree" "{}"
      post_json "/api/reserves/prove" '{"reservesAda":10000}'
      ;;
    voting)
      post_json "/api/vote" '{"voterLabel":"voter1","vote":1}'
      curl -fsS "${BASE_URL}/api/results"
      printf '\n'
      ;;
    airdrop)
      post_json "/api/airdrop/claim" '{"name":"Alice"}'
      curl -fsS "${BASE_URL}/api/airdrop/status"
      printf '\n'
      ;;
    dpp)
      post_json "/api/dpp/verify" '{"id":"BAT-SN001","type":"product"}'
      post_json "/api/dpp/mint" '{"id":"BAT-SN001"}'
      curl -fsS "${BASE_URL}/api/dpp/status"
      printf '\n'
      ;;
  esac
}

if [ "${STOP_DEMO}" = "true" ]; then
  stop_demo
  exit 0
fi

wait_for_http "${PROVIDER_HEALTH_URL}" "Blockfrost-compatible provider" 120
top_up_demo_wallet
clean_demo_cache

echo "Starting ${SERVICE} with ${COMPOSE_FILE} ..."
compose up -d --build "${SERVICE}"
wait_for_http "${BASE_URL}${HEALTH}" "${SERVICE}" 240

open_ui

if [ "${RUN_FLOW}" = "true" ]; then
  run_flow
fi

echo "UI: ${BASE_URL}"
echo "Provider: ${PROVIDER_BASE_URL}"

if [ "${FOLLOW_LOGS}" = "true" ]; then
  compose logs -f "${SERVICE}"
fi
