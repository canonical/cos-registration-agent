#!/bin/bash -eu

IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"

logger -t "${SNAP_NAME}" "Reading device configuration from confdb view"

# Write device.yaml content to a temp file
DEVICE_CONFIG="$(snapctl get --view :confdb-configuration device)"
. "${SNAP}/usr/bin/write-tmp-file.sh" "${DEVICE_CONFIG}" DEVICE_CONFIG_FILE

echo "Using confdb-provided device configuration file: ${DEVICE_CONFIG_FILE}"
logger -t "${SNAP_NAME}" "Using confdb-provided device configuration file: ${DEVICE_CONFIG_FILE}"

# Build optional arguments for asset directories
CMD_ARGS=()

# Grafana dashboards
GRAFANA_DASHBOARDS="$(snapctl get --view :confdb-configuration grafana.dashboards || true)"
if [[ -n "${GRAFANA_DASHBOARDS}" ]] && [[ "${GRAFANA_DASHBOARDS}" != "null" ]]; then
  . "${SNAP}/usr/bin/write-confdb-map-to-tmp-dir.sh" "${GRAFANA_DASHBOARDS}" json GRAFANA_DASHBOARDS_DIR
  CMD_ARGS+=(--grafana-dashboards "${GRAFANA_DASHBOARDS_DIR}")
fi

# Foxglove layouts
FOXGLOVE_LAYOUTS="$(snapctl get --view :confdb-configuration foxglove.layouts || true)"
if [[ -n "${FOXGLOVE_LAYOUTS}" ]] && [[ "${FOXGLOVE_LAYOUTS}" != "null" ]]; then
  . "${SNAP}/usr/bin/write-confdb-map-to-tmp-dir.sh" "${FOXGLOVE_LAYOUTS}" json FOXGLOVE_LAYOUTS_DIR
  CMD_ARGS+=(--foxglove-studio-dashboards "${FOXGLOVE_LAYOUTS_DIR}")
fi

# Loki alert rules
LOKI_ALERT_RULES="$(snapctl get --view :confdb-configuration loki.alerts || true)"
if [[ -n "${LOKI_ALERT_RULES}" ]] && [[ "${LOKI_ALERT_RULES}" != "null" ]]; then
  . "${SNAP}/usr/bin/write-confdb-map-to-tmp-dir.sh" "${LOKI_ALERT_RULES}" rules LOKI_ALERT_RULES_DIR
  CMD_ARGS+=(--loki-alert-rule-files "${LOKI_ALERT_RULES_DIR}")
fi

# Prometheus alert rules
PROMETHEUS_ALERT_RULES="$(snapctl get --view :confdb-configuration prometheus.alerts || true)"
if [[ -n "${PROMETHEUS_ALERT_RULES}" ]] && [[ "${PROMETHEUS_ALERT_RULES}" != "null" ]]; then
  . "${SNAP}/usr/bin/write-confdb-map-to-tmp-dir.sh" "${PROMETHEUS_ALERT_RULES}" rules PROMETHEUS_ALERT_RULES_DIR
  CMD_ARGS+=(--prometheus-alert-rule-files "${PROMETHEUS_ALERT_RULES_DIR}")
fi

# Identity token
GLOBAL_ARGS=()
if [[ -f "${IDENTITY_TOKEN_FILE_PATH}" ]]; then
  GLOBAL_ARGS+=(--token-file "${IDENTITY_TOKEN_FILE_PATH}")
fi

"${SNAP}/bin/cos-registration-agent" \
  --shared-data-path "${SNAP_COMMON}/rob-cos-shared-data" \
  "${GLOBAL_ARGS[@]}" \
  update \
  -c "${DEVICE_CONFIG_FILE}" \
  "${CMD_ARGS[@]}"
