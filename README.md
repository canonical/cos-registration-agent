
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
The COS registration agent required systemd.

To install the `cos-registration-agent``, you must build and install the snap:
```
snapcraft
```
```
sudo snap install cos-registration-agent*.snap --dangerous
```

## Usage

```
usage: cos-registration-agent [-h] [--grafana-service-token GRAFANA_SERVICE_TOKEN]
                              [--grafana-dashboard GRAFANA_DASHBOARD]
                              [--shared-data-path]
                              [--config CONFIG] [--robot-unique-id ROBOT_UNIQUE_ID]
                              [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                              {setup,update,write-uid,delete} ...

positional arguments:
  {setup,update,write-uid,delete}
                        Action to perform
    setup               Register device and add custom dashboards device
    update              Update custom device data and dashboards
    write-uid           Write device unique ID to a file
    delete              Delete device from server
options:
  -h, --help            show this help message and exit
  --shared-data-path SHARED_DATA_PATH
                        The path to which the relevant common devices app files
                        such as robot-unique-id are stored. (default: current_directory)
  --config CONFIG       Config file path. (default: None)
  --robot-unique-id ROBOT_UNIQUE_ID
                        Robot unique ID, default set to machine ID. (default: None)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        set the logging level (default: None)

Args that start with '--' can also be set in a config file (specified via
--config). Config file syntax allows:
key=value, flag=true, stuff=[a,b,c] (for details, see syntax at
https://goo.gl/R74nmi).
In general, command-line values override config file values which override
defaults.
```

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
url: localhost
# grafana
grafana-service-token: glsa_12345
grafana-dashboard: tests/dashboard.json
shared-data-path: $SNAP_COMMON/rob-cos-shared-data setup
```
Then we can call `cos-registration-agent` with:
```
cos-registration-agent --config ./config.yaml setup
```

## Development

Read the [CONTRIBUTING.md](CONTRIBUTING.md) file.
