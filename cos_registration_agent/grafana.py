import json
import logging
from pathlib import Path

import configargparse
from grafana_client import GrafanaApi
from grafana_client.client import GrafanaClientError, TokenAuth

logger = logging.getLogger(__name__)

parser = configargparse.get_argument_parser()

parser.add_argument(
    "--grafana-service-token",
    help="Grafana service token",
    required=True,
    type=str,
)
parser.add_argument(
    "--grafana-dashboard",
    help="Path to the grafana dashboard",
    required=True,
    type=Path,
)


class Grafana:
    """Grafana interfacing with the grafana backend."""

    def __init__(self, url: str, service_token: str, robot_uid: str):
        self.robot_uid = robot_uid
        self.robot_dashboard_folder = "robot-" + robot_uid
        self.client = GrafanaApi(
            host=url,
            url_path_prefix="cos-grafana",
            auth=TokenAuth(token=service_token),
        )

        if not self.client.health.check():
            raise RuntimeError(
                "Grafana health check failed, \
                  make sure the server is reachable"
            )

    def setup(self, grafana_dashboard_path: Path):
        try:
            self._setup_dashboard_folder()
        except GrafanaClientError as e:
            logger.error(
                "Failed to create dashboard folder, \
                  maybe the setup was already done."
            )
            raise RuntimeError(e)
        self._upload_dashboard(grafana_dashboard_path)

    def update(self, grafana_dashboard_path: Path):
        self._upload_dashboard(grafana_dashboard_path)

    def _setup_dashboard_folder(self):
        return self.client.folder.create_folder(
            self.robot_dashboard_folder, uid=self.robot_uid
        )

    def _upload_dashboard(self, dashboard_path: Path):
        with open(dashboard_path) as dashboard:
            dashboard_json = json.load(dashboard)
            dashboard_json["folderUid"] = self.robot_uid
            logger.debug("Dashboard json:")
            logger.debug(dashboard_json)
            return self.client.dashboard.update_dashboard(dashboard_json)
