
# COS registration agent

COS registration agent is responsible for identifying the robot to the COS server as well as uploading robot specific data to the server (dashboard, UID, etc).

---
# cos_registration_agent

[![codecov](https://codecov.io/gh/ubuntu-robotics/cos-registration-agent/branch/main/graph/badge.svg?token=cos-registration-agent_token_here)](https://codecov.io/gh/ubuntu-robotics/cos-registration-agent)
[![CI](https://github.com/ubuntu-robotics/cos-registration-agent/actions/workflows/main.yml/badge.svg)](https://github.com/ubuntu-robotics/cos-registration-agent/actions/workflows/main.yml)

## Features

The `cos_registration_agent` can perform two actions: `setup` and `update`.

### Setup
Setup is reponsible for identifying and configuring the COS for a given agent. This action will failed if called a second time by a device.
#### Grafana
- Create device dashboard folder
- Upload initial dashboard
### Update
Update is making sure that the configuration of the COS for a given device gets updated over time. This action is meant to be called multiple times.
#### Grafana
- Upload dashboard

## Installation
To install the `cos-registration-agent``, you must build and install the snap:
```
snapcraft
```
```
sudo snap install cos-registration-agent*.snap --dangerous
```

## Usage

```
usage: cos-registration-agent [-h] --grafana-service-token GRAFANA_SERVICE_TOKEN --grafana-dashboard
                              GRAFANA_DASHBOARD [--config CONFIG] --url URL [--robot-unique-id ROBOT_UNIQUE_ID]
                              [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                              {setup,update}

positional arguments:
  {setup,update}        action to perform

optional arguments:
  -h, --help            show this help message and exit
  --grafana-service-token GRAFANA_SERVICE_TOKEN
                        grafana service token (default: None)
  --grafana-dashboard GRAFANA_DASHBOARD
                        path to the grafana dashboard (default: None)
  --config CONFIG       Config file path. (default: None)
  --url URL             COS base IP/URL (default: None)
  --robot-unique-id ROBOT_UNIQUE_ID
                        Robot unique ID, default set to machine ID. (default: None)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        set the logging level (default: None)

Args that start with '--' can also be set in a config file (specified via --config). Config file syntax allows:
key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). In general, command-line
values override config file values which override defaults.
```

Setup command example:

```
cos-registration-agent --url localhost --grafana-service-token glsa_123456789 --grafana-dashboard tests/dashboard.json setup
```

Alternatively a configuration file can be used instead of argument flags.
With the following configuration file `config.yaml`:

```
url: localhost
# grafana
grafana-service-token: glsa_12345
grafana-dashboard: tests/dashboard.json
```
Then we can call `cos-registration-agent` with:
```
cos-registration-agent --config ./config.yaml setup
```

## Development

Read the [CONTRIBUTING.md](CONTRIBUTING.md) file.
