#!/usr/bin/bash -e

CONFIGURATION_FILE_PATH="$SNAP_COMMON/configuration/device.yaml"

CONFIG_PATH_PARAMETER="$(snapctl get configuration-path)"

# Use fallback configuration mechanism if the configuration-path is set
if [ -n "${CONFIG_PATH_PARAMETER}" ]; then
    CONFIGURATION_FILE_PATH="/root/${CONFIG_PATH_PARAMETER}/device.yaml"
fi

if [ ! -f "${CONFIGURATION_FILE_PATH}" ]; then
    echo "Configuration file '${CONFIGURATION_FILE_PATH}' does not exist."
    logger -t ${SNAP_NAME} "Configuration file '${CONFIGURATION_FILE_PATH}' does not exist."
    exit 1
fi

echo "Using configuration file: ${CONFIGURATION_FILE_PATH}."
logger -t ${SNAP_NAME} "Using configuration file: ${CONFIGURATION_FILE_PATH}."

# Retrieve the directory at which the configuration is stored
CONFIGURATION_DIR_PATH="$(dirname "${CONFIGURATION_FILE_PATH}")"

# Set the registration command args based on configuration
REGISTRATION_CMD_ARGS=""

# Check if grafan_dashboards directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/grafana_dashboards" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --grafana-dashboards ${CONFIGURATION_DIR_PATH}/grafana_dashboards"
fi

# Check if foxglove_layouts directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/foxglove_layouts" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --foxglove-studio-dashboards ${CONFIGURATION_DIR_PATH}/foxglove_layouts"
fi

# Check if loki_alert_rules directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/loki_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --loki-alert-rule-files ${CONFIGURATION_DIR_PATH}/loki_alert_rules"
fi

# Check if prometheus_alert_rules directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/prometheus_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --prometheus-alert-rule-files ${CONFIGURATION_DIR_PATH}/prometheus_alert_rules"
fi

# Call the update command with the args
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ${SNAP}/bin/cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} update -c ${CONFIGURATION_FILE_PATH}
