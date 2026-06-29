#!/usr/bin/env sh
set -eu

if [ -z "${APP_NAME:-}" ]; then
  echo "APP_NAME is required" >&2
  exit 2
fi

if [ "${RUN_YACI:-true}" = "true" ]; then
  echo "Waiting for Yaci DevKit at ${YACI_HEALTH_URL} ..."
  attempts=0
  until curl -fsS "${YACI_HEALTH_URL}" >/dev/null; do
    attempts=$((attempts + 1))
    if [ "${attempts}" -ge 60 ]; then
      echo "Timed out waiting for Yaci DevKit. Start Yaci manually or set YACI_HEALTH_URL." >&2
      exit 1
    fi
    sleep 2
  done
  JAVA_OPTS="${JAVA_OPTS:-} -Dzeroj.yaci.txWaitAttempts=${ZEROJ_YACI_TX_WAIT_ATTEMPTS:-90} -Dzeroj.yaci.txWaitMillis=${ZEROJ_YACI_TX_WAIT_MILLIS:-2000}"
  export JAVA_OPTS
  exec "./bin/${APP_NAME}" --yaci "$@"
fi

exec "./bin/${APP_NAME}" "$@"
