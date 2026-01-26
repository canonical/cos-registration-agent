"""The COS registration agent."""

import json
import logging
from pathlib import Path
from posixpath import join as urljoin
from typing import Any, Optional, Set, Tuple, Union

import requests
import yaml

logger = logging.getLogger(__name__)

API_VERSION = str("api/v1/")
HEADERS_APPLICATION_JSON = {"Content-Type": "application/json"}


def _validate_token(token_file: Optional[Path] = None) -> Optional[str]:
    if token_file:
        if not token_file.is_file():
            error_message = f"The bearer token file path provided \
                doesn't exist: {token_file}"
            logger.error(error_message)
            raise FileNotFoundError(error_message)

        return token_file.read_text()
    return None


class CosRegistrationServerClient:
    """COS registration server HTTP client."""

    def __init__(
        self, cos_server_url: str, bearer_token: Optional[str] = None
    ):
        """Init COS Registration server client."""
        self.cos_server_url = urljoin(cos_server_url, API_VERSION)

        self.headers = {}
        if bearer_token:
            self.headers["Authorization"] = f"bearer {bearer_token}"

    def get(self, endpoint: str, params: Any = None) -> Any:
        """HTTP GET to the COS Registration server."""
        response = requests.get(
            urljoin(self.cos_server_url, endpoint),
            headers=self.headers,
            params=params,
            verify=False,
            timeout=10,
        )
        return response

    def post(
        self, endpoint: str, data: Any = None, headers: Any = None
    ) -> Any:
        """HTTP POST to the COS Registration server."""
        response = requests.post(
            urljoin(self.cos_server_url, endpoint),
            json=data,
            verify=False,
            headers=self.headers | (headers or {}),
            timeout=10,
        )
        return response

    def patch(self, endpoint: str, data: Any = None) -> Any:
        """HTTP PATCH to the COS Registration server."""
        response = requests.patch(
            urljoin(self.cos_server_url, endpoint),
            json=data,
            verify=False,
            timeout=10,
        )
        return response

    def delete(self, endpoint: str, data: Any = None) -> Any:
        """HTTP DELETE to the COS Registration server."""
        response = requests.delete(
            urljoin(self.cos_server_url, endpoint),
            json=data,
            verify=False,
            timeout=10,
        )
        return response


class CosRegistrationAgent:
    """COS registration agent interfacing with the COS backend."""

    def __init__(
        self,
        cos_server_url: str,
        device_id: str,
        token_file: Optional[Path] = None,
    ):
        """Init COS registration agent."""
        self.cos_client = CosRegistrationServerClient(
            cos_server_url, bearer_token=_validate_token(token_file)
        )
        self.device_id = device_id
        self.devices_endpoint = "devices/"
        self.applications_endpoint = "applications/"
        self.health_endpoint = "health/"
        self.device_id_endpoint = urljoin(
            self.devices_endpoint, self.device_id + "/"
        )

        server_health_status = self.cos_client.get(self.health_endpoint)
        if not server_health_status.status_code == 200:
            error_message = "COS registration server health check failed, \
                    make sure the server is reachable "+cos_server_url+self.health_endpoint
            logger.error(error_message)
            raise RuntimeError(error_message)

    def register_device(
        self,
        **fields: Union[str, Set[str]],
    ) -> None:
        """Register device on the COS registration server.

        Args:
        **fields: keyword arguments representing device fields.
                    Each field is provided as a key-value pair.
        """
        device_data = dict(fields)

        device_data["uid"] = self.device_id

        response = self.cos_client.post(
            self.devices_endpoint,
            data=device_data,
            headers=HEADERS_APPLICATION_JSON,
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
        response = self.cos_client.delete(self.device_id_endpoint)
        if response.status_code != 204:
            logger.error(
                f"Could not delete device, \
                response status code is {response.status_code}: \
                {response.json()}"
            )
        logger.info("Device deleted")

    def _get_device_data(self):
        """Retrieve devices data from the COS Registration server."""
        response = self.cos_client.get(self.device_id_endpoint)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(
                f"Could not find device data at {self.device_id_endpoint}"
            )
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

        device_patched_data = {**device_current_data, **updated_device_data}

        for key, value in device_patched_data.items():
            if key in device_current_data and key in updated_device_data:
                device_patched_data[key] = value

        response = self.cos_client.patch(
            self.device_id_endpoint, data=device_patched_data
        )
        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch device data. \
                Error: {error_details}. \
                Status code: {response.status_code}"
            )

    def _get_dashboard_data(self, dashboard_id_endpoint: str):
        """Retrieve dashboard data from the COS registration server.

        Args:
        - dashboard_id_endpoint(str): the endpoint to get the dashboard data.
        """
        response = self.cos_client.get(dashboard_id_endpoint)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            logger.warning(
                f"Could not find dashboard data at {dashboard_id_endpoint}."
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
                    dashboard_id_endpoint = self._get_dashboard_id_endpoint(
                        dashboard_id, application
                    )
                    current_dashboard_data = self._get_dashboard_data(
                        dashboard_id_endpoint
                    )
                    if current_dashboard_data is None:
                        self._add_dashboard(dashboard_file, application)
                    else:
                        updated_dashboard = json.dumps(updated_dashboard_data)
                        if current_dashboard_data != updated_dashboard:
                            self._patch_dashboard(
                                dashboard_id_endpoint,
                                updated_dashboard_data,
                            )

    def _add_dashboard(self, dashboard_file: Path, application: str):
        application_endpoint = urljoin(
            self.applications_endpoint, application + "/dashboards/"
        )
        with open(dashboard_file) as dashboard:
            dashboard_content_json = json.load(dashboard)
            dashboard_name = Path(dashboard_file).stem
            dashboard_json = {
                "uid": dashboard_name,
                "dashboard": dashboard_content_json,
            }
            response = self.cos_client.post(
                application_endpoint,
                data=dashboard_json,
                headers=HEADERS_APPLICATION_JSON,
            )
            if response.status_code != 201:
                logger.error(
                    f"Could not add dashboad, \
                    response status code is {response.status_code}: \
                    {response.json()}"
                )

            logger.info("Dashboard added")

    def _patch_dashboard(
        self, dashboard_id_endpoint: str, updated_dashboard_data: dict
    ) -> None:
        dashboard_json = {
            "dashboard": updated_dashboard_data,
        }
        response = self.cos_client.patch(
            dashboard_id_endpoint, data=dashboard_json
        )

        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch dashboard. \
                Error: {error_details}"
            )

    def _get_dashboard_id_endpoint(self, dashboard_id, application) -> str:
        dashbard_id_endpoint = urljoin(
            self.applications_endpoint,
            application + "/dashboards/" + dashboard_id + "/",
        )
        return dashbard_id_endpoint

    def _get_rule_file_data(self, rule_file_id_endpoint: str):
        """Retrieve rule file data from the COS registration server.

        Args:
        - rule_file_id_endpoint(str): the endpoint to get the rule file data.
        """
        response = self.cos_client.get(rule_file_id_endpoint)
        if response.status_code == 200:
            json_data = response.json()
            return yaml.load(json_data["rules"], yaml.SafeLoader)
        elif response.status_code == 404:
            logger.warning(
                f"Could not find rule file data at {rule_file_id_endpoint}."
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
                    rule_file_id_endpoint = self._get_rule_file_id_endpoint(
                        rule_file_id, application
                    )
                    current_rule_file_data = self._get_rule_file_data(
                        rule_file_id_endpoint
                    )
                    if current_rule_file_data is None:
                        self._add_rule_file(rule_file, application)
                    else:
                        updated_data = yaml.dump(updated_rule_file_data)
                        if current_rule_file_data != updated_data:
                            self._patch_rule_file(
                                rule_file_id_endpoint,
                                updated_data,
                            )

    def _add_rule_file(self, rule_file: Path, application: str):
        application_endpoint = urljoin(
            self.applications_endpoint, application, "alert_rules/"
        )
        with open(rule_file) as rule_file_data:
            rule_file_content_yaml = yaml.safe_load(rule_file_data)
            rule_file_name = Path(rule_file).stem
            rule_json = {
                "uid": rule_file_name,
                "rules": yaml.dump(rule_file_content_yaml),
            }
            response = self.cos_client.post(
                application_endpoint,
                data=rule_json,
                headers=HEADERS_APPLICATION_JSON,
            )
            if response.status_code != 201:
                logger.error(
                    f"Could not add the rule file, \
                    response status code is {response.status_code}: \
                    {response.json()}"
                )

            logger.info("Rule file added")

    def _patch_rule_file(
        self, rule_file_id_endpoint: str, updated_data: str
    ) -> None:
        rule_json = {
            "rules": updated_data,
        }
        response = self.cos_client.patch(rule_file_id_endpoint, data=rule_json)
        if response.status_code != 200:
            error_details = response.json()
            logger.error(
                f"Failed to patch rule file. \
                Error: {error_details}"
            )

    def _get_rule_file_id_endpoint(self, rule_file_id, application) -> str:
        rule_file_id_endpoint = urljoin(
            self.applications_endpoint,
            application + "/alert_rules/" + rule_file_id + "/",
        )
        return rule_file_id_endpoint

    def get_device_tls_certificate(self) -> Optional[Tuple[str, str]]:
        """Retrieve device tls cert and key from the COS registration server.

        Args:
        - device_uid(str): the device uid.
        """
        tls_certs_url = urljoin(self.device_id_endpoint, "certificate")
        response = self.cos_client.get(tls_certs_url)
        if response.status_code == 200:
            data = response.json()
            cert = data.get("certificate")
            key = data.get("private_key")
            return cert, key
        elif response.status_code == 404:
            logger.error(
                f"Could not retrieve device \
                         TLS certificate and key at \
                         {tls_certs_url}"
            )
            return None
        else:
            raise FileNotFoundError(
                f"Failed to retrieve device TLS certificate data. \
                Status code: {response.status_code}"
            )
