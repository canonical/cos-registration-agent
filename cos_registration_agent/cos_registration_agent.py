import json
import logging
from typing import Set, Union
import requests
from urllib.parse import urljoin
from pathlib import Path

logger = logging.getLogger(__name__)

API_VERSION = "api/v1/"
HEADERS = {"Content-Type": "application/json"}


class CosRegistrationAgent:
    """Cos registration agent interfacing with the cos backend."""

    def __init__(self, cos_server_url: str):
        """Init Cos Registration Agent."""
        self.cos_server_url = cos_server_url.rstrip("/") + "/"
        self.cos_devices_url = urljoin(
            self.cos_server_url, API_VERSION + "devices/"
        )
        self.cos_device_url = urljoin(
            self.cos_server_url, API_VERSION + "device/"
        )
        self.cos_applications_url = urljoin(
            self.cos_server_url, API_VERSION + "applications/"
        )
        self.cos_application_url = urljoin(
            self.cos_server_url, API_VERSION + "application/"
        )

        server_status = requests.get(self.cos_devices_url)
        if not server_status.status_code == 200:
            error_message = "COS registration server health check failed, \
                    make sure the server is reachable"
            logger.error(error_message)
            raise RuntimeError(error_message)

    def register_device(self, **fields: Union[str, Set[str]]):
        """Register device on the COS registration server.

        Args:
        **fields: Keyword arguments representing device fields.
                    Each field is provided as a key-value pair.
        """
        device_data = {}
        for field, value in fields.items():
            device_data[field] = value

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

        logger.info("Device created")

    def delete_device(self, device_id: str):
        """Delete device from the COS registration server.

        Args:
        - device_id(str): the id of the device to be deleted
        """
        device_id_url = urljoin(self.cos_devices_url, device_id)
        logger.error(device_id_url)
        response = requests.delete(device_id_url)
        if response.status_code != 204:
            logger.error(
                f"Could not delete device, \
                response status code is {response.status_code}: \
                {response.json()}"
            )
        logger.info("Device deleted")

    def _get_device_data(self, device_id: str):
        """Retrieve devices data from the COS Registration server.

        Args:
        - device_id(str): the id of the device
        """
        device_id_url = urljoin(self.cos_devices_url, device_id)
        response = requests.get(device_id_url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(f"could not find device {device_id} data")
            return None
        else:
            raise Exception(
                f"Failed to retrieve device data. \
                Status code: {response.status_code}"
            )

    def patch_device(self, device_id: str, updated_device_data: dict):
        """Patch device data on the COS Registration server.

        Args:
        - device_id(str): the id of the device to be deleted
        - updated_device_data(dict): a dictionary containing the data
          to be pached
        """
        device_current_data = self._get_device_data(device_id)
        device_id_url = urljoin(self.cos_devices_url, device_id + "/")

        device_patched_data = {**device_current_data, **updated_device_data}

        for key, value in device_patched_data.items():
            if key in device_current_data and key in updated_device_data:
                if isinstance(device_current_data[key], list):
                    merged = list(set(device_current_data[key] + value))
                else:
                    merged = updated_device_data[key]
                device_patched_data[key] = merged

        response = requests.patch(device_id_url, json=device_patched_data)
        if response.status_code != 201:
            error_details = response.json()
            logger.error(
                f"Failed to patch device data. \
                Error: {error_details}"
            )

    def _get_dashboard_data(self, dashboard_id: str):
        """Retrieve dashboard data from the COS Registration server.

        Args:
        - dashboard_id(str): the id of the dashboard
        """
        dashbard_id_url = urljoin(self.cos_application_url, dashboard_id + "/")
        response = requests.get(dashbard_id_url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.error(f"could not find dashboard {dashboard_id} data")
            return None
        else:
            raise Exception(
                f"Failed to retrieve device data. \
                Status code: {response.status_code}"
            )

    def add_dashboards(self, dashboard_path: Path, application: str):
        """Register dashboards on the COS registration server.

        Args:
        - dashboard_path(Path): The path in which the dashboards are stored.
        - application(str): The name of the application.
        """
        directory = Path(dashboard_path)

        for dashboard_file in directory.iterdir():
            if dashboard_file.suffix == ".json" and dashboard_file.is_file():
                self._add_dashboard(dashboard_file, application)

    def _add_dashboard(self, dashboard_file: Path, application: str):
        application_url = urljoin(
            self.cos_applications_url, application + "/dashboards/"
        )
        with open(dashboard_file) as dashboard:
            dashboard_json = json.load(dashboard)
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

    def patch_dashboards(self, dashboard_path: Path, application: str):
        """Patch dashboard data on the COS Registration server.

        Args:
        - dashboard_path(str): The path in which the dashboards are stored.
        If there are new dashboards upload them, if there are changes in
        the dashboards already uploaded patch them.
        - application(str): The name of the application
        """
        directory = Path(dashboard_path)
        for dashboard_file in directory.iterdir():
            if dashboard_file.suffix == ".json" and dashboard_file.is_file():
                with open(dashboard_file, "r") as f:
                    updated_dashboard_data = json.load(f)
                    dashboard_id = updated_dashboard_data.get("id")
                    current_dashboard_data = self._get_dashboard_data(
                        dashboard_id
                    )
                    if updated_dashboard_data is None:
                        self._add_dashboard(dashboard_file, application)
                    else:
                        if current_dashboard_data != updated_dashboard_data:
                            self._patch_dashboard(
                                dashboard_id,
                                updated_dashboard_data,
                                application,
                            )

    def _patch_dashboard(
        self, dashboard_id: str, updated_dashboard_data: dict, application: str
    ):
        dashboard_url = urljoin(
            self.cos_application_url,
            application + "/dashboards/" + dashboard_id + "/",
        )
        response = requests.patch(dashboard_url, json=updated_dashboard_data)
        if response.status_code != 201:
            error_details = response.json()
            logger.error(
                f"Failed to patch device data. \
                Error: {error_details}"
            )
