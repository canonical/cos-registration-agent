#!/bin/sh

# Updated for confdb-first architecture
# device.yaml is now synced from confdb to $SNAP_COMMON/device.yaml
# This script is idempotent - can be called multiple times safely
# NOTE: Not using -e so we can capture and log error codes properly

CONFIGURATION_FILE_PATH="${SNAP_COMMON}/device.yaml"
IDENTITY_TOKEN_FILE_PATH="${SNAP_COMMON}/rob-cos-shared-data/identity/token.txt"
REGISTRATION_MARKER="${SNAP_COMMON}/.device-registered"

# Check if already registered (idempotent check)
if [ -f "${REGISTRATION_MARKER}" ]; then
    logger -t ${SNAP_NAME} "Device already registered"
    exit 0
fi

if [ ! -f "${CONFIGURATION_FILE_PATH}" ]; then
    logger -t ${SNAP_NAME} "Configuration file does not exist"
    exit 1
fi

# Check if configuration has placeholder values (not yet configured)
if grep -q "placeholder" "${CONFIGURATION_FILE_PATH}"; then
    logger -t ${SNAP_NAME} "Configuration not ready (contains placeholders)"
    exit 1
fi

# Validate required fields are present and non-empty
if ! grep -q "^url:" "${CONFIGURATION_FILE_PATH}" || \
   ! grep -q "^uid:" "${CONFIGURATION_FILE_PATH}"; then
    logger -t ${SNAP_NAME} "Configuration missing required fields"
    exit 1
fi

# Check that url and uid have actual values (not just the keys)
URL_VALUE=$(grep "^url:" "${CONFIGURATION_FILE_PATH}" | cut -d' ' -f2-)
UID_VALUE=$(grep "^uid:" "${CONFIGURATION_FILE_PATH}" | cut -d' ' -f2-)

if [ -z "$URL_VALUE" ] || [ -z "$UID_VALUE" ]; then
    logger -t ${SNAP_NAME} "Configuration fields are empty"
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

# Call the registration command - action (setup) comes first, then config file
if ${SNAP}/bin/cos-registration-agent setup --config "${CONFIGURATION_FILE_PATH}" --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} 2>&1; then
    logger -t ${SNAP_NAME} "Device registered successfully"
    touch "${REGISTRATION_MARKER}"
else
    EXIT_CODE=$?
    logger -t ${SNAP_NAME} "Registration failed with exit code ${EXIT_CODE}"
    exit ${EXIT_CODE}
fi

logger -t ${SNAP_NAME} "Successfully registered the device."

snapctl start --enable ${SNAP_NAME}.update-device-configuration 2>&1
