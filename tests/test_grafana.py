import mock
import os
import pytest
import unittest
import json

from cos_registration_agent.grafana import Grafana
from grafana_client.client import GrafanaClientError


def rootdir():
    return os.path.dirname(os.path.abspath(__file__))


class TestGrafana(unittest.TestCase):
    @mock.patch("grafana_client.elements.Health.check", return_value=True)
    def test_grafana_health_check(self, mock_health):
        """Test object creation."""
        grafana_client = Grafana("http://localhost:3000", "token", "uid")

        mock_health.assert_called_once()

    @mock.patch("grafana_client.elements.Health.check", return_value=False)
    def test_grafana_health_check_failed(self, mock_health):
        """Test object creation."""
        with pytest.raises(RuntimeError) as e:
            grafana_client = Grafana("http://localhost:3000", "token", "uid")
        assert (
            str(e.value)
            == "Grafana health check failed, \
                  make sure the server is reachable"
        )

        mock_health.assert_called_once()

    @mock.patch(
        "grafana_client.elements.Dashboard.update_dashboard", return_value=None
    )
    @mock.patch(
        "grafana_client.elements.Folder.create_folder", return_value=None
    )
    @mock.patch("grafana_client.elements.Health.check", return_value=True)
    def test_grafana_setup(self, mock_health, mock_folder, mock_dashboard):
        """Test grafana setup action."""

        dashboard_path = os.path.join(rootdir(), "dashboard.json")

        grafana_client = Grafana("http://localhost:3000", "token", "robot-uid")
        grafana_client.setup(dashboard_path)

        mock_folder.assert_called_once_with(
            grafana_client.robot_dashboard_folder,
            uid=grafana_client.robot_uid,
        )
        with open(dashboard_path) as dashboard:
            mock_dashboard.assert_called_once_with(json.load(dashboard))

    @mock.patch(
        "grafana_client.elements.Dashboard.update_dashboard", return_value=None
    )
    @mock.patch(
        "grafana_client.elements.Folder.create_folder",
        side_effect=GrafanaClientError(401, "", "Error"),
    )
    @mock.patch("grafana_client.elements.Health.check", return_value=True)
    def test_grafana_setup_failed(
        self, mock_health, mock_folder, mock_dashboard
    ):
        dashboard_path = os.path.join(rootdir(), "dashboard.json")

        grafana_client = Grafana("http://localhost:3000", "token", "robot-uid")

        with pytest.raises(RuntimeError) as e:
            grafana_client.setup(dashboard_path)
        assert str(e.value) == "Error"

        mock_folder.assert_called_once_with(
            grafana_client.robot_dashboard_folder,
            uid=grafana_client.robot_uid,
        )
        mock_dashboard.assert_not_called()

    @mock.patch(
        "grafana_client.elements.Dashboard.update_dashboard", return_value=None
    )
    @mock.patch("grafana_client.elements.Health.check", return_value=True)
    def test_grafana_update(self, mock_health, mock_dashboard):
        dashboard_path = os.path.join(rootdir(), "dashboard.json")

        grafana_client = Grafana("http://localhost:3000", "token", "robot-uid")

        grafana_client.update(dashboard_path)

        with open(dashboard_path) as dashboard:
            mock_dashboard.assert_called_once_with(json.load(dashboard))
