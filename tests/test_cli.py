import unittest
from unittest.mock import ANY, patch, MagicMock
import sys
import configargparse
from pathlib import Path

from cos_registration_agent import cli


class TestCli(unittest.TestCase):
    def setUp(self):
        self.old_argv = sys.argv
        # we do that to get a fresh argparse at every test
        configargparse._parsers = {}
        sys.argv = [self._testMethodName]

        self.robot_uid = "robot-1"
        self.robot_uid_args = ["--uid", self.robot_uid]

        self.robot_ip = "1.2.3.4"

        self.server_url = "http://my-cos-server"
        self.server_url_args = ["--url", self.server_url]

        self.grafana_dashboards_path = "grafana_path"
        self.grafana_dashboards_path_arg = [
            f"--grafana-dashboards={self.grafana_dashboards_path}",
        ]
        self.generic_args = self.grafana_dashboards_path_arg

        self.foxglove_dashboards_path = "foxglove_path"
        self.foxglove_dashboards_path_arg = [
            f"--foxglove-studio-dashboards={self.foxglove_dashboards_path}",
        ]
        self.generic_args.extend(self.foxglove_dashboards_path_arg)

        self.loki_rule_files_path = "loki_path"
        self.loki_rule_files_path_arg = [
            f"--loki-rule-files={self.loki_rule_files_path}",
        ]
        self.generic_args.extend(self.loki_rule_files_path_arg)

        self.prometheus_rule_files_path = "prometheus_path"
        self.prometheus_rule_files_path_arg = [
            f"--prometheus-rule-files={self.prometheus_rule_files_path}",
        ]
        self.generic_args.extend(self.prometheus_rule_files_path_arg)

    def tearDown(self):
        sys.argv = self.old_argv

    def test_parse_help(self):
        sys.argv.extend(["--help"])
        try:
            cli.main()
        except SystemExit as e:
            self.assertEqual(e.code, 0)
        else:
            self.assertTrue(False)

    @patch("cos_registration_agent.cli.SSHKeysManager.write_keys")
    @patch("cos_registration_agent.cli.CosRegistrationAgent")
    @patch("cos_registration_agent.cli.get_machine_ip_address")
    def test_setup(
        self, mock_get_machine_ip, MockCosRegistrationAgent, mock_write_keys
    ):
        mock_cos_registration_agent = MockCosRegistrationAgent.return_value
        mock_get_machine_ip.return_value = self.robot_ip
        setup_args = ["setup"]
        setup_args.extend(self.robot_uid_args)
        setup_args.extend(self.server_url_args)
        sys.argv.extend(self.generic_args)
        sys.argv.extend(setup_args)
        cli.main()

        mock_cos_registration_agent.patch_dashboards.assert_called()

        mock_cos_registration_agent.patch_rule_files.assert_called()

        mock_cos_registration_agent.register_device.assert_called_once_with(
            address=self.robot_ip,
            public_ssh_key=ANY,
            grafana_dashboards=[],
            foxglove_dashboards=[],
            loki_rule_files=[],
            prometheus_rule_files=[],
        )

    @patch("cos_registration_agent.cli.CosRegistrationAgent")
    @patch("cos_registration_agent.cli.get_machine_ip_address")
    def test_update(self, mock_get_machine_ip, MockCosRegistrationAgent):
        mock_cos_registration_agent = MockCosRegistrationAgent.return_value
        self.robot_ip = "4.3.2.1"
        mock_get_machine_ip.return_value = self.robot_ip
        update_args = ["update"]
        update_args.extend(self.robot_uid_args)
        update_args.extend(self.server_url_args)
        sys.argv.extend(self.generic_args)
        sys.argv.extend(update_args)
        cli.main()

        mock_cos_registration_agent.patch_dashboards.assert_called()

        patched_device_arguments = {"address": self.robot_ip}
        mock_cos_registration_agent.patch_device.assert_called_once_with(
            patched_device_arguments
        )

    @patch("cos_registration_agent.cli.CosRegistrationAgent")
    @patch("cos_registration_agent.cli.get_machine_ip_address")
    def test_delete(self, mock_get_machine_ip, MockCosRegistrationAgent):
        mock_cos_registration_agent = MockCosRegistrationAgent.return_value
        delete_args = ["delete"]
        delete_args.extend(self.robot_uid_args)
        delete_args.extend(self.server_url_args)
        sys.argv.extend(self.generic_args)
        sys.argv.extend(delete_args)
        cli.main()

        mock_cos_registration_agent.delete_device.assert_called_once_with()
