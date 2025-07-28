
# COS registration agent

COS registration agent is responsible for identifying the robot to the
COS registration server as well as uploading robot specific data
to the server (dashboard, UID, etc).

---
# cos_registration_agent

[![codecov](https://codecov.io/gh/canonical/cos-registration-agent/branch/main/graph/badge.svg?token=cos-registration-agent_token_here)](https://codecov.io/gh/canonical/cos-registration-agent)
[![CI](https://github.com/canonical/cos-registration-agent/actions/workflows/main.yml/badge.svg)](https://github.com/canonical/cos-registration-agent/actions/workflows/main.yml)

## Features

The `cos_registration_agent` can perform four actions: `setup`, `update`, `write-uid` and `delete`.

### Setup
Setup is reponsible for identifying and configuring the COS for a given device.
This action registers first any custom dashboard provided with the device
and the device itself.
This action will fail if called by an already registered device.
### Update
Update is making sure that the configuration of the COS for a given device
gets updated over time. This action is meant to be called multiple times.
### Write-uid
Write-uid is responsible for writing the device unique ID in the SNAP_COMMON folder
where it is made available for other snaps on the device.
### Delete
Delete is responsible for deleting the device from COS registration server.

## Installation
The COS registration agent requires systemd.

### Local

To install the `cos-registration-agent`, you can build it first with:
```
snapcraft
```

and finally install it with:

```
sudo snap install cos-registration-agent*.snap --dangerous
```

### Snap Store

The snap can also be installed directly from the Snap Store with:

```
sudo snap install cos-registration-agent --edge
```

The snap is available on the Snap Store for both amd64 and arm64.

## Usage

```
usage: cos-registration-agent [-h] [--config CONFIG] [--url URL] [--shared-data-path SHARED_DATA_PATH] [--grafana-dashboards GRAFANA_DASHBOARDS]
                              [--foxglove-studio-dashboards FOXGLOVE_STUDIO_DASHBOARDS] [--loki-alert-rule-files LOKI_ALERT_RULE_FILES]
                              [--prometheus-alert-rule-files PROMETHEUS_ALERT_RULE_FILES] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                              {setup,update,write-uid,delete} ...

positional arguments:
  {setup,update,write-uid,delete}
                        Action to perform
    setup               Register device and add custom dashboards
    update              Update custom device data and dashboards
    write-uid           Write device unique ID to a file
    delete              Delete device from server

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       Config file path. (default: None)
  --url URL             COS base IP/URL (default: None)
  --shared-data-path SHARED_DATA_PATH
                        The path to which the relevant common devices app files such as robot-unique-id are stored. (default:
                        /home/guillaume/code/rob-cos/cos-registration-agent)
  --grafana-dashboards GRAFANA_DASHBOARDS
                        Path to the grafana dashboard (default: None)
  --foxglove-studio-dashboards FOXGLOVE_STUDIO_DASHBOARDS
                        Path to the foxglove dashboard (default: None)
  --loki-alert-rule-files LOKI_ALERT_RULE_FILES
                        Path to the Loki alert rule files (default: None)
  --prometheus-alert-rule-files PROMETHEUS_ALERT_RULE_FILES
                        Path to the Prometheus alert rule files (default: None)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (default: None)

Positional arguments as well as args that start with '--' can also be set in a config file (specified via --config). Config file syntax allows: key=value, flag=true,
stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). In general, command-line values override config file values which override
defaults.
```

### TLS

To support TLS communication with the COS for devices server,
the REQUESTS_CA_BUNDLE environment variable is set in the Snap applications.
This ensures that the Python requests library uses the system's default CA bundle located at `etc/ssl/certs/ca-certificates.crt`.

This setup allows the applications to verify server certificates,
including self-signed or internally issued certificates,
as long as they are installed on the device and the CA bundle is updated using `update-ca-certificates`.

This means, that when using a self-signed certificate or a certificate issued by an internal CA,
TLS communication will work by installing the certificate on the device and updating the CA bundle with .

The variable will not affect the behaviour of the agent with no TLS.

### Examples

Setup device with custom grafana dashboard example:
```
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data setup --url http://127.0.0.1:8000/ --grafana-dashboards /home/giuseppe/device_dashboards/grafana_dashboards  --device-grafana-dashboards my_dashboard1 my_dashboard2

```

Patch grafana dashboards:
```
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data update --url http://127.0.0.1:8000/ --grafana-dashboards /device_dashboards/grafana_dashboards
```

Update device ssh keys:
```
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data update --url http://127.0.0.1:8000/ --update-ssh-keys
```

Delete device from COS server:
```
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data delete --url http://127.0.0.1:8000/
```

## Config

Alternatively a configuration file can be used instead of argument flags.
With the following configuration file `config.yaml`:

```
url: http://cos-server/cos-robotics-model-cos-registration-server/
uid: my-robot-uid
grafana-dashboards: path/to_grafana_dashboards/
foxglove-studio-dashboards: path/to_foxglove_studio_dashboards/
loki-alert-rule-files: path/to_loki_alert_rule_files
prometheus-alert-rule-files: path/to_prometheus_alert_rule_files
setup
device-grafana-dashboards: [dashboard-1, dashboard-2]
device-foxglove-dashboards: [dashboard-3, dashboard-4]
device-loki-alert-rule-files: None
device-prometheus-alert-rule-files: [alert-rule-file-1]

```
Then we can call `cos-registration-agent` with:
```
cos-registration-agent --config ./config.yaml
```

## Development

Read the [CONTRIBUTING.md](CONTRIBUTING.md) file.
