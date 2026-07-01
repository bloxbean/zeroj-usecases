#!/usr/bin/env sh
set -eu

APP_JAR="${APP_JAR:-/app/app.jar}"
SERVER_PORT="${SERVER_PORT:-8080}"
BLOCKFROST_BASE_URL="${BLOCKFROST_BASE_URL:-http://host.docker.internal:8080/api/v1/}"
DEFAULT_PROVIDER_HEALTH_URL="${BLOCKFROST_BASE_URL%/}/epochs/latest"
PROVIDER_HEALTH_URL="${PROVIDER_HEALTH_URL:-${BF_HEALTH_URL:-${YACI_HEALTH_URL:-${DEFAULT_PROVIDER_HEALTH_URL}}}}"
DEMO_CACHE_SOURCE_DIR="${DEMO_CACHE_SOURCE_DIR:-/opt/zeroj-demo-cache}"
DEMO_CACHE_TARGET_DIR="${DEMO_CACHE_TARGET_DIR:-/app/data}"

curl_provider() {
  if [ -n "${BLOCKFROST_PROJECT_ID:-}" ]; then
    curl -fsS -H "project_id: ${BLOCKFROST_PROJECT_ID}" "$1"
  else
    curl -fsS "$1"
  fi
}

seed_demo_cache() {
  if [ "${DEMO_CACHE_SEED_ENABLED:-true}" != "true" ]; then
    echo "Demo cache seeding disabled."
    return 0
  fi
  if [ ! -d "${DEMO_CACHE_SOURCE_DIR}" ]; then
    return 0
  fi

  mkdir -p "${DEMO_CACHE_TARGET_DIR}"
  if find "${DEMO_CACHE_TARGET_DIR}" -maxdepth 1 -type f -name 'setup-*.bin' | grep -q .; then
    echo "Runtime setup cache already exists in ${DEMO_CACHE_TARGET_DIR}; demo cache seed skipped."
    return 0
  fi

  seeded=0
  for path in "${DEMO_CACHE_SOURCE_DIR}"/* "${DEMO_CACHE_SOURCE_DIR}"/.[!.]*; do
    [ -e "${path}" ] || continue
    name="$(basename "${path}")"
    if [ ! -e "${DEMO_CACHE_TARGET_DIR}/${name}" ]; then
      cp -R "${path}" "${DEMO_CACHE_TARGET_DIR}/${name}"
      seeded=1
    fi
  done

  if [ "${seeded}" = "1" ]; then
    echo "Seeded demo cache from ${DEMO_CACHE_SOURCE_DIR} into ${DEMO_CACHE_TARGET_DIR}."
  fi
}

seed_demo_cache

if [ "${WAIT_FOR_PROVIDER:-${RUN_YACI:-true}}" = "true" ]; then
  echo "Waiting for Blockfrost-compatible provider at ${PROVIDER_HEALTH_URL} ..."
  attempts=0
  until curl_provider "${PROVIDER_HEALTH_URL}" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "${attempts}" -ge "${YACI_WAIT_ATTEMPTS:-120}" ]; then
      echo "Timed out waiting for Blockfrost-compatible provider at ${PROVIDER_HEALTH_URL}." >&2
      exit 1
    fi
    sleep "${YACI_WAIT_SECONDS:-2}"
  done
fi

JAVA_OPTS="${JAVA_OPTS:-} -Dzeroj.allowInsecureTrustedSetup=${ZEROJ_ALLOW_INSECURE_TRUSTED_SETUP:-true} --enable-native-access=ALL-UNNAMED"
export JAVA_OPTS

exec java ${JAVA_OPTS} -jar "${APP_JAR}" --server.port="${SERVER_PORT}" "$@"
