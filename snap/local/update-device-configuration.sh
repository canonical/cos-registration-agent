#!/usr/bin/bash -e

CONFIGURATION_FILE_PATH="$SNAP_COMMON/configuration/device.yaml"

$SNAP/bin/cos-registration-agent \
  --shared-data-path $SNAP_COMMON/rob-cos-shared-data \
  --grafana-dashboards $SNAP_COMMON/configuration/grafana_dashboards \
  --foxglove-studio-dashboards $SNAP_COMMON/configuration/foxglove_layouts \
  --loki-rule-files $SNAP_COMMON/configuration/loki_alert_rules \
  --prometheus-rule-files $SNAP_COMMON/configuration/prometheus_alert_rules \
  update -c $CONFIGURATION_FILE_PATH
