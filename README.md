
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
The setup action can also be called with the `--generate-device-tls-certificate` to
generate TLS certificate and private key for a device.
This action will fail if called by an already registered device.
### Update
Update is making sure that the configuration of the COS for a given device
gets updated over time.
The update action can also be called with the `--generate-device-tls-certificate` to
regenerate TLS certificate and private key for a device.
This action is meant to be called multiple times.
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
    setup               Register device, add custom dashboards and generate device TLS certificates
    update              Update custom device data and dashboards and device TLS certificates
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
the `REQUESTS_CA_BUNDLE` environment variable is set in the snap.
This ensures that the Python `requests` library uses the system's default CA bundle located at `/etc/ssl/certs/ca-certificates.crt`.

This setup allows the applications to verify server certificates,
including self-signed or internally issued certificates,
as long as they are installed on the device and the CA bundle is updated using `update-ca-certificates`.

This environment variable does not affect the agent’s behavior when TLS is not used.

### Examples

#### Using Confdb (Recommended)

When connected to `rob-cos-demo-configuration`, the URL and UID are automatically read from confdb:

```bash
# Connect confdb interface (first time only)
sudo snap connect cos-registration-agent:device-cos-settings-observe

# Setup device - URL and UID from confdb
cos-registration-agent setup

# Setup with custom grafana dashboard
cos-registration-agent setup --grafana-dashboards /home/giuseppe/device_dashboards/grafana_dashboards --device-grafana-dashboards my_dashboard1 my_dashboard2

# Setup with TLS certificate generation
cos-registration-agent setup --generate-device-tls-certificate

# Update device configuration
cos-registration-agent update

# Update with dashboard changes
cos-registration-agent update --grafana-dashboards /device_dashboards/grafana_dashboards

# Update device SSH keys
cos-registration-agent update --update-ssh-keys

# Regenerate TLS certificates
cos-registration-agent update --generate-device-tls-certificate

# Delete device from COS server
cos-registration-agent delete
```

#### Using Command-Line Arguments (Without Confdb)

When confdb is not available, specify URL explicitly:

```bash
# Setup device with custom grafana dashboard
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data setup --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ --grafana-dashboards /home/giuseppe/device_dashboards/grafana_dashboards --device-grafana-dashboards my_dashboard1 my_dashboard2

# Setup device with generation of TLS certificates
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data setup --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ --generate-device-tls-certificate

# Patch grafana dashboards
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data update --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ --grafana-dashboards /device_dashboards/grafana_dashboards

# Update device ssh keys
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data update --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ --update-ssh-keys

# Update device with regeneration of TLS certificates
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data update --url http://192.168.1.100:8000/production-fleet-cos-registration-server/ --generate-device-tls-certificate

# Delete device from COS server
cos-registration-agent --shared-data-path $SNAP_COMMON/rob-cos-shared-data delete --url http://192.168.1.100:8000/production-fleet-cos-registration-server/
```

## Configuration

### Configuration Priority

The `cos-registration-agent` supports multiple configuration sources with the following priority (highest to lowest):

1. **Confdb** (via `device-cos-settings` schema) - Primary source when connected to `rob-cos-demo-configuration`
2. **Command-line arguments** - Override confdb values
3. **Configuration file** - Fallback when confdb is not available
4. **Defaults** - Built-in fallback values

### Confdb Integration

When the snap is connected to `rob-cos-demo-configuration` via the `device-cos-settings-observe` interface, configuration is automatically read from confdb:

```bash
# Connect to confdb
sudo snap connect cos-registration-agent:device-cos-settings-observe

# Configuration is now automatically available from confdb
# No need to specify --url or --uid flags
cos-registration-agent setup
```

Confdb provides:
- **Device UID**: Auto-generated from machine-id
- **COS Registration URL**: Computed from `rob-cos-ip` + `model-name` + `registration-server-endpoint`

To check current confdb values:
```bash
sudo snap run --shell cos-registration-agent
snapctl get --view :device-cos-settings-observe -d
```

### Configuration File

Alternatively, when confdb is not available, a configuration file can be used:

With the following configuration file `config.yaml`:

```yaml
url: http://192.168.1.100:8000/production-fleet-cos-registration-server/
uid: my-robot-uid
generate-device-tls-certificate: True
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

Then call `cos-registration-agent` with:
```bash
cos-registration-agent --config ./config.yaml
```

### Command-Line Override

Command-line arguments can override confdb values when needed:
```bash
# Use different URL than confdb
cos-registration-agent --url http://test-server:8000/test-model-cos-registration-server/ setup

# Use different UID than confdb
cos-registration-agent --uid custom-device-id setup
```

## Development

Read the [CONTRIBUTING.md](CONTRIBUTING.md) file.
