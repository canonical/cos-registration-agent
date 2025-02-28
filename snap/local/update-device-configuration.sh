#!/usr/bin/bash -e

CONFIGURATION_FILE_PATH="$SNAP_COMMON/configuration/device.yaml"

# Check if grafan_dashboards directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/grafana_dashboards" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --grafana-dashboards ${SNAP_COMMON}/configuration/grafana_dashboards"
fi

# Check if foxglove_layouts directory exists in configuration
if [ -d "${SNAP_COMMON}/configuration/foxglove_layouts" ]; then
    REGISTRATION_CMD_ARGS="${REGISTRATION_CMD_ARGS} --foxglove-studio-dashboards ${SNAP_COMMON}/configuration/foxglove_layouts"
fi

# Call the update command with the args
${SNAP}/bin/cos-registration-agent --shared-data-path ${SNAP_COMMON}/rob-cos-shared-data ${REGISTRATION_CMD_ARGS} update -c ${CONFIGURATION_FILE_PATH}
