"""The COS registration agent."""

import json
import logging
from pathlib import Path
from typing import Optional, Set, Tuple, Union
from urllib.parse import urljoin

import requests
import yaml

logger = logging.getLogger(__name__)

API_VERSION = "api/v1/"
HEADERS = {"Content-Type": "application/json"}


class CosRegistrationAgent:
    """COS registration agent interfacing with the COS backend."""

    def __init__(self, cos_server_url: str, device_id: str):
        """Init COS registration agent."""
        self.cos_server_url = cos_server_url
        self.cos_devices_url = urljoin(
            self.cos_server_url, API_VERSION + "devices/"
        )
        self.cos_applications_url = urljoin(
            self.cos_server_url, API_VERSION + "applications/"
        )
        self.cos_health_url = urljoin(
            self.cos_server_url, API_VERSION + "health/"
        )
        self.device_id = device_id
        self.device_id_url = urljoin(
            self.cos_devices_url, self.device_id + "/"
        )

        server_health_status = requests.get(self.cos_health_url)
        if not server_health_status.status_code == 200:
            error_message = "COS registration server health check failed, \
                    make sure the server is reachable"
            logger.error(error_message)
            raise RuntimeError(error_message)

    def register_device(
        self,
        **fields: Union[str, Set[str]],
    ):
        """Register device on the COS registration server.

        Args:
        **fields: keyword arguments representing device fields.
                    Each field is provided as a key-value pair.
        """
        device_data = dict(fields)

        device_data["uid"] = self.device_id

        json_data = json.dumps(device_data)
        response = requests.post(
            self.cos_devices_url, data=json_data, headers=HEADERS
        )
        if response.status_code != 201:
            logger.error(
                f"Could not create device, \
                response status code is {response.status_code}: \
                {response.json()}"
            )
            raise SystemError

        logger.info("Device created")

    def delete_device(self) -> None:
        """Delete device from the COS registration server."""
        response = requests.delete(self.device_id_url)
        if response.status_code != 204:
            logger.error(
                f"Could not delete device, \
                response status code is {response.status_code}: \
                {response.json()}"
            )
        logger.info("Device deleted")

    def _get_device_data(self):
        """Retrieve devices data from the COS Registration server."""
        response = requests.get(self.device_id_url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(f"Could not find device data at {self.device_id_url}")
            return None
        else:
            raise FileNotFoundError(
                f"Failed to retrieve device data. \
                Status code: {response.status_code}"
            )

    def patch_device(self, updated_device_data: dict) -> None:
        """Patch device data on the COS Registration server.

        Args:
        - updated_device_data(dict): a dictionary containing the data
          to be pached.
        """
        if not updated_device_data:
            return

        device_current_data = self._get_device_data()
        device_id_url = self.device_id_url

        device_patched_data = {**device_current_data, **updated_device_data}

        for key, value in device_patched_data.items():
            if key in device_current_data and key in updated_device_data:
                device_patched_data[key] = value

        response = requests.patch(device_id_url, json=device_patched_data)
        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch device data. \
                Error: {error_details}. \
                Status code: {response.status_code}"
            )

    def _get_dashboard_data(self, dashboard_id_url: str):
        """Retrieve dashboard data from the COS registration server.

        Args:
        - dashboard_id_url(str): the url to get the dashboard data from.
        """
        response = requests.get(dashboard_id_url)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            logger.warning(
                f"Could not find dashboard data at {dashboard_id_url}."
                "Uploading it."
            )
            return None
        else:
            raise FileNotFoundError(
                f"Failed to retrieve dashboard data. \
                Status code: {response.status_code}"
            )

    def patch_dashboards(self, dashboard_path: Path, application: str) -> None:
        """Add or patch dashboards on the COS registration server.

        Args:
        - dashboard_path(str): the path in which the dashboards are stored.
        If there are new dashboards upload them, if there are changes in
        the dashboards already uploaded patch them.
        - application(str): the name of the application.
        """
        directory = Path(dashboard_path)
        for dashboard_file in directory.iterdir():
            if dashboard_file.suffix == ".json" and dashboard_file.is_file():
                with open(dashboard_file, "r") as f:
                    updated_dashboard_data = json.load(f)
                    dashboard_id = dashboard_file.stem
                    dashboard_id_url = self._get_dashboard_id_url(
                        dashboard_id, application
                    )
                    current_dashboard_data = self._get_dashboard_data(
                        dashboard_id_url
                    )
                    if current_dashboard_data is None:
                        self._add_dashboard(dashboard_file, application)
                    else:
                        updated_dashboard = json.dumps(updated_dashboard_data)
                        if current_dashboard_data != updated_dashboard:
                            self._patch_dashboard(
                                dashboard_id_url,
                                updated_dashboard_data,
                            )

    def _add_dashboard(self, dashboard_file: Path, application: str):
        application_url = urljoin(
            self.cos_applications_url, application + "/dashboards/"
        )
        with open(dashboard_file) as dashboard:
            dashboard_content_json = json.load(dashboard)
            dashboard_name = Path(dashboard_file).stem
            dashboard_json = {
                "uid": dashboard_name,
                "dashboard": dashboard_content_json,
            }
            response = requests.post(
                application_url,
                json=dashboard_json,
                headers=HEADERS,
            )
            if response.status_code != 201:
                logger.error(
                    f"Could not add dashboad, \
                    response status code is {response.status_code}: \
                    {response.json()}"
                )

            logger.info("Dashboard added")

    def _patch_dashboard(
        self, dashboard_id_url: str, updated_dashboard_data: dict
    ) -> None:
        dashboard_json = {
            "dashboard": updated_dashboard_data,
        }
        response = requests.patch(dashboard_id_url, json=dashboard_json)

        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch dashboard. \
                Error: {error_details}"
            )

    def _get_dashboard_id_url(self, dashboard_id, application) -> str:
        dashbard_id_url = urljoin(
            self.cos_applications_url,
            application + "/dashboards/" + dashboard_id + "/",
        )
        return dashbard_id_url

    def _get_rule_file_data(self, rule_file_id_url: str):
        """Retrieve rule file data from the COS registration server.

        Args:
        - rule_file_id_url(str): the url to get the rule file data from.
        """
        response = requests.get(rule_file_id_url)
        if response.status_code == 200:
            json_data = response.json()
            return yaml.load(json_data["rules"], yaml.SafeLoader)
        elif response.status_code == 404:
            logger.warning(
                f"Could not find rule file data at {rule_file_id_url}."
                "Uploading it."
            )
            return None
        else:
            raise FileNotFoundError(
                f"Failed to retrieve rule file data. \
                Status code: {response.status_code}"
            )

    def patch_rule_files(
        self, rule_files_path: Path, application: str
    ) -> None:
        """Add or patch rule files on the COS registration server.

        Args:
        - rule_file_path(str): the path in which the rule files are stored.
        If there are new rule files upload them, if there are changes in
        the rule files already uploaded patch them.
        - application(str): the name of the application.
        """
        directory = Path(rule_files_path)
        for rule_file in directory.iterdir():
            if rule_file.suffix == ".rules" and rule_file.is_file():
                with open(rule_file, "r") as f:
                    updated_rule_file_data = yaml.safe_load(f)
                    rule_file_id = rule_file.stem
                    rule_file_id_url = self._get_rule_file_id_url(
                        rule_file_id, application
                    )
                    current_rule_file_data = self._get_rule_file_data(
                        rule_file_id_url
                    )
                    if current_rule_file_data is None:
                        self._add_rule_file(rule_file, application)
                    else:
                        updated_data = yaml.dump(updated_rule_file_data)
                        if current_rule_file_data != updated_data:
                            self._patch_rule_file(
                                rule_file_id_url,
                                updated_data,
                            )

    def _add_rule_file(self, rule_file: Path, application: str):
        application_url = urljoin(
            self.cos_applications_url, application + "/alert_rules/"
        )
        with open(rule_file) as rule_file_data:
            rule_file_content_yaml = yaml.safe_load(rule_file_data)
            rule_file_name = Path(rule_file).stem
            rule_json = {
                "uid": rule_file_name,
                "rules": yaml.dump(rule_file_content_yaml),
            }
            response = requests.post(
                application_url,
                json=rule_json,
                headers=HEADERS,
            )
            if response.status_code != 201:
                logger.error(
                    f"Could not add the rule file, \
                    response status code is {response.status_code}: \
                    {response.json()}"
                )

            logger.info("Rule file added")

    def _patch_rule_file(
        self, rule_file_id_url: str, updated_data: str
    ) -> None:
        rule_json = {
            "rules": updated_data,
        }
        response = requests.patch(rule_file_id_url, json=rule_json)
        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch rule file. \
                Error: {error_details}"
            )

    def _get_rule_file_id_url(self, rule_file_id, application) -> str:
        rule_file_id_url = urljoin(
            self.cos_applications_url,
            application + "/alert_rules/" + rule_file_id + "/",
        )
        return rule_file_id_url

    def get_device_tls_certificate(self) -> Optional[Tuple[str, str]]:
        """Retrieve device tls cert and key from the COS registration server.

        Args:
        - device_uid(str): the device uid.
        """
        tls_certs_url = urljoin(self.device_id_url, "certificate")
        response = requests.get(tls_certs_url)
        if response.status_code == 200:
            data = response.json()
            cert = data.get("certificate")
            key = data.get("private_key")
            return cert, key
        elif response.status_code == 404:
            logger.error(f"Could not retrieve device \
                         TLS certificate and key at \
                         {tls_certs_url}")
            return None
        else:
            raise FileNotFoundError(
                f"Failed to retrieve device TLS certificate data. \
                Status code: {response.status_code}"
            )
