#!/bin/sh -e

# Updated for confdb-first architecture
# device.yaml is now synced from confdb to $SNAP_COMMON/device.yaml

CONFIGURATION_FILE_PATH="${SNAP_COMMON}/device.yaml"
IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"

if [ ! -f "${CONFIGURATION_FILE_PATH}" ]; then
    logger -t ${SNAP_NAME} "Configuration file does not exist"
    exit 1
fi

# Get configuration directory from rob-cos-demo-configuration via content interface
# Dashboards and alerts are from the configuration snap, not device.yaml
CONFIGURATION_DIR_PATH="${SNAP_COMMON}/configuration"

# Set the registration command args based on configuration
REGISTRATION_CMD_ARGS=""

# Check if grafana_dashboards directory exists in configuration
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

# Check if identity token exists in configuration
if [ -f "${IDENTITY_TOKEN_FILE_PATH}" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --token-file ${IDENTITY_TOKEN_FILE_PATH}"
fi

# Call the update command - action (update) comes first, then config file
${SNAP}/bin/cos-registration-agent update --config "${CONFIGURATION_FILE_PATH}" --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS}
