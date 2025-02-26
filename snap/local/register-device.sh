#!/bin/sh -e

CONFIGURATION_FILE_PATH=$SNAP_COMMON/configuration/device.yaml

if [ ! -f "$CONFIGURATION_FILE_PATH" ]; then
    echo "Configuration file '$CONFIGURATION_FILE_PATH' does not exist."
    exit 1
fi

REGISTRATION_CMD="$SNAP/bin/cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data"

# Check if grafan_dashboards directory exists in configuration
if [ -d "$SNAP_COMMON/configuration/grafana_dashboards" ]; then
    REGISTRATION_CMD="$REGISTRATION_CMD --grafana-dashboards $SNAP_COMMON/configuration/grafana_dashboards"
fi

# Check if foxglove_layouts directory exists in configuration
if [ -d "$SNAP_COMMON/configuration/foxglove_layouts" ]; then
    REGISTRATION_CMD="$REGISTRATION_CMD --foxglove-studio-dashboards $SNAP_COMMON/configuration/foxglove_layouts"
fi

REGISTRATION_CMD="$REGISTRATION_CMD setup -c $CONFIGURATION_FILE_PATH"
eval "$REGISTRATION_CMD"

snapctl start --enable ${SNAP_NAME}.update-device-configuration 2>&1
