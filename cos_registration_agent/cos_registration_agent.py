"""The COS registration agent."""

import json
import logging
import time
from pathlib import Path
from posixpath import join as urljoin
from typing import Any, Optional, Set, Union

import requests
import yaml

from cos_registration_agent.tls_utils import (
    generate_csr,
    generate_private_key,
    store_certificate,
    store_private_key,
)

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
        self,
        cos_server_url: str,
        bearer_token: Optional[str] = None,
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
        certs_dir: Optional[str] = None,
    ):
        """Init COS registration agent."""
        self.cos_client = CosRegistrationServerClient(
            cos_server_url, bearer_token=_validate_token(token_file)
        )
        self.device_id = device_id
        self.devices_endpoint = "devices/"
        self.applications_endpoint = "applications/"
        self.health_endpoint = "health/"
        self.certificate_endpoint = "certificate/"
        self.device_id_endpoint = urljoin(
            self.devices_endpoint, self.device_id + "/"
        )
        self.device_certificates_endpoint = urljoin(
            self.device_id_endpoint, self.certificate_endpoint
        )

        self.certs_dir = certs_dir

        server_health_status = self.cos_client.get(self.health_endpoint)
        if not server_health_status.status_code == 200:
            error_message = "COS registration server health check failed, \
                    make sure the server is reachable"
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

    def request_device_tls_certificate(self, device_ip: str) -> bool:
        """Generate and store a private key, then submit a CSR to the server.

        Args:
            device_ip: The IP address of the device to include in CSR SAN.

        Returns:
            bool: True if CSR was successfully submitted, False otherwise.
        """
        if not self.certs_dir:
            logger.error("Certs directory not configured.")
            return False

        logger.info("Generating private key and CSR...")

        private_key = generate_private_key()
        csr_pem_str = generate_csr(
            private_key, common_name=self.device_id, device_ip=device_ip
        )

        try:
            response = self.cos_client.post(
                self.device_certificates_endpoint, data={"csr": csr_pem_str}
            )
            if response.status_code == 202:
                logger.info(
                    "CSR submitted successfully," "storing the private key."
                )
                store_private_key(private_key, self.certs_dir)
                return True
            else:
                logger.error(
                    f"Failed to submit CSR. Status: {response.status_code}, "
                    f"Response: {response.text}"
                )
                return False
        except (requests.RequestException, OSError) as e:
            logger.error(f"Certificate request failed: {e}")
            return False

    def _get_certificate_data(self, device_certificates_endpoint: str) -> dict:
        """
        Retrieve certificate data from the COS Registration server.

        Args:
            device_certificates_endpoint(str): the endpoint
                to get the certificate data.

        Raises:
            FileNotFoundError: If the certificate for the device is not found.
            requests.exceptions.HTTPError: For other HTTP errors.
        """
        response = self.cos_client.get(device_certificates_endpoint)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            raise FileNotFoundError("Certificate for device not found.")
        else:
            raise requests.exceptions.HTTPError(
                f"Failed to retrieve certificate data. \
                Status code: {response.status_code}"
            )

    def _process_certificate_response(self, certificate_data: dict) -> bool:
        """
        Process the certificate response data.

        Args:
            certificate_data(dict): The data retrieved from the server.
        Returns:
            bool: True if the certificate was stored, False otherwise.
        Raises:
            RuntimeError: If certs directory is not configured.
            PermissionError: If the CSR was denied by the server.
        """
        status = certificate_data.get("status")

        if status == "signed":
            chain = certificate_data.get("chain")
            if not chain:
                logger.error("Status signed but missing certificate chain.")
                return False

            if not self.certs_dir:
                raise RuntimeError("Certs directory not configured.")

            store_certificate(chain, self.certs_dir)
            return True

        if status == "denied":
            raise PermissionError("CSR was denied by the server.")

        if status == "pending":
            logger.info("Certificate still pending...")
            return False

        logger.warning(f"Unknown status received: {status}")
        return False

    def poll_for_certificate(self, timeout_seconds: int = 600) -> bool:
        """Poll the server for the signed certificate.

        Args:
            timeout_seconds: Maximum time to wait for certificate
                (default: 600s/10min).

        Returns:
            bool: True if certificate was successfully received and
                stored, False otherwise.
        """
        logger.info(
            f"Starting certificate polling "
            f"(timeout: {timeout_seconds} seconds)..."
        )

        start_time = time.time()
        interval = 60  # Poll every 60 seconds
        while time.time() < start_time + timeout_seconds:
            try:
                certificate_data = self._get_certificate_data(
                    self.device_certificates_endpoint
                )
                if certificate_data:
                    if self._process_certificate_response(certificate_data):
                        return True
            except requests.RequestException as e:
                logger.error(f"Error while polling for certificate: {e}")

            time.sleep(interval)

        logger.error(
            "Timeout reached: Certificate was not signed within "
            f"{timeout_seconds} seconds."
        )
        raise TimeoutError("Timeout: failed to obtain signed certificate.")
