#!/bin/sh -e

# This script updates the device configuration on the COS server
# Configuration is read from confdb (no config file needed)

IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"
CONFIGURATION_DIR_PATH="${SNAP_COMMON}/configuration"

logger -t ${SNAP_NAME} "Starting device configuration update"

# Build update command args
REGISTRATION_CMD_ARGS=""

# Check if grafana_dashboards directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/grafana_dashboards" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --grafana-dashboards ${CONFIGURATION_DIR_PATH}/grafana_dashboards"
    logger -t ${SNAP_NAME} "Found grafana_dashboards directory"
fi

# Check if foxglove_layouts directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/foxglove_layouts" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --foxglove-studio-dashboards ${CONFIGURATION_DIR_PATH}/foxglove_layouts"
    logger -t ${SNAP_NAME} "Found foxglove_layouts directory"
fi

# Check if loki_alert_rules directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/loki_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --loki-alert-rule-files ${CONFIGURATION_DIR_PATH}/loki_alert_rules"
    logger -t ${SNAP_NAME} "Found loki_alert_rules directory"
fi

# Check if prometheus_alert_rules directory exists in configuration
if [ -d "${CONFIGURATION_DIR_PATH}/prometheus_alert_rules" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --prometheus-alert-rule-files ${CONFIGURATION_DIR_PATH}/prometheus_alert_rules"
    logger -t ${SNAP_NAME} "Found prometheus_alert_rules directory"
fi

# Check if identity token exists
if [ -f "${IDENTITY_TOKEN_FILE_PATH}" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --token-file ${IDENTITY_TOKEN_FILE_PATH}"
    logger -t ${SNAP_NAME} "Using identity token from ${IDENTITY_TOKEN_FILE_PATH}"
fi

# Call the update command
# Note: --url and --uid are optional; if not provided, they will be read from confdb
# The cos-registration-agent will automatically get configuration from confdb
logger -t ${SNAP_NAME} "Executing: cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} update"

${SNAP}/bin/cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} update

logger -t ${SNAP_NAME} "Device configuration update completed"
