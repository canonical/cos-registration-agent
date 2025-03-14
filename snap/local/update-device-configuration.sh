#!/usr/bin/bash -e

CONFIGURATION_FILE_PATH="$SNAP_COMMON/configuration/device.yaml"

CONFIG_PATH_PARAMETER="$(snapctl get configuration-path)"

# use fallback configuration mechanism if the configuration-path is set
if [ -n "${CONFIG_PATH_PARAMETER}" ]; then
    CONFIGURATION_FILE_PATH=${CONFIG_PATH_PARAMETER}/device.yaml
fi

if [ ! -f "${CONFIGURATION_FILE_PATH}" ]; then
    >&2 echo "Configuration file '${CONFIGURATION_FILE_PATH}' does not exist."
    exit 1
fi

>&2 echo "Using configuration file: $CONFIGURATION_FILE_PATH"

# Set the registration command args based on configuration
REGISTRATION_CMD_ARGS=""

# Check if grafan_dashboards directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/grafana_dashboards" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --grafana-dashboards ${SNAP_COMMON}/configuration/grafana_dashboards"
fi

# Check if foxglove_layouts directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/foxglove_layouts" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --foxglove-studio-dashboards ${SNAP_COMMON}/configuration/foxglove_layouts"
fi

# Check if loki_alert_rules directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/loki_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --loki-rules-files ${SNAP_COMMON}/configuration/loki_alert_rules"
fi

# Check if prometheus_alert_rules directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/prometheus_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --prometheus-rules-files ${SNAP_COMMON}/configuration/prometheus_alert_rules"
fi

# Call the update command with the args
>&2 echo "update device with $CONFIGURATION_FILE_PATH"
logger -t ${SNAP_NAME} "update device with $CONFIGURATION_FILE_PATH"
#${SNAP}/bin/cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} update -c ${CONFIGURATION_FILE_PATH}
