#!/bin/sh -e

CONFIGURATION_FILE_PATH=${SNAP_COMMON}/configuration/device.yaml

if [ ! -f "${CONFIGURATION_FILE_PATH}" ]; then
    echo "Configuration file '${CONFIGURATION_FILE_PATH}' does not exist."
    exit 1
fi

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

# Call the registration command with the args
${SNAP}/bin/cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} setup -c ${CONFIGURATION_FILE_PATH}

snapctl start --enable ${SNAP_NAME}.update-device-configuration 2>&1

