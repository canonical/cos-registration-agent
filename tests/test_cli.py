import unittest
from unittest.mock import ANY, patch
import sys
import configargparse

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

        self.bearer_token_file = "path/to/secret/token.txt"
        self.bearer_token_arg = [f"--token-file={self.bearer_token_file}"]

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

        self.loki_alert_rule_files_path = "loki_path"
        self.loki_alert_rule_files_path_arg = [
            f"--loki-alert-rule-files={self.loki_alert_rule_files_path}",
        ]
        self.generic_args.extend(self.loki_alert_rule_files_path_arg)

        self.prometheus_alert_rule_files_path = "prometheus_path"
        self.prometheus_alert_rule_files_path_arg = [
            f"--prometheus-alert-rule-files={self.prometheus_alert_rule_files_path}",
        ]
        self.generic_args.extend(self.prometheus_alert_rule_files_path_arg)

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
    def test_setup_variants(
        self, mock_get_machine_ip, MockCosRegistrationAgent, mock_write_keys
    ):
        test_cases = [
            {
                "name": "without_tls",
                "extra_args": [],
            },
            {
                "name": "with_tls",
                "extra_args": ["--generate-device-tls-certificate"],
            },
        ]

        for case in test_cases:
            with self.subTest(name=case["name"]):
                configargparse._parsers = {}

                sys.argv = ["cos-registration-agent"]

                mock_cos_registration_agent = (
                    MockCosRegistrationAgent.return_value
                )
                mock_get_machine_ip.return_value = self.robot_ip

                setup_args = ["setup"]
                setup_args.extend(self.robot_uid_args)
                setup_args.extend(self.server_url_args)
                setup_args.extend(case["extra_args"])
                sys.argv.extend(self.generic_args)
                sys.argv.extend(setup_args)
                cli.main()

                mock_cos_registration_agent.patch_dashboards.assert_called()
                mock_cos_registration_agent.patch_rule_files.assert_called()

                if "--generate-device-tls-certificate" in case["extra_args"]:
                    mock_cos_registration_agent.request_device_tls_certificate.assert_called()
                    mock_cos_registration_agent.poll_for_certificate.assert_called()
                else:
                    mock_cos_registration_agent.request_device_tls_certificate.assert_not_called()
                    mock_cos_registration_agent.poll_for_certificate.assert_not_called()

                mock_cos_registration_agent.register_device.assert_called_once_with(
                    address=self.robot_ip,
                    public_ssh_key=ANY,
                    grafana_dashboards=[],
                    foxglove_dashboards=[],
                    loki_alert_rule_files=[],
                    prometheus_alert_rule_files=[],
                )
                mock_cos_registration_agent.register_device.reset_mock()

    @patch("cos_registration_agent.cli.SSHKeysManager.write_keys")
    @patch("cos_registration_agent.cli.CosRegistrationAgent")
    @patch("cos_registration_agent.cli.get_machine_ip_address")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_identity_protected_setup(
        self,
        mock_is_file,
        mock_get_machine_ip,
        MockCosRegistrationAgent,
        mock_write_keys,
    ):
        mock_get_machine_ip.return_value = self.robot_ip
        setup_args = ["setup"]
        setup_args.extend(self.robot_uid_args)
        setup_args.extend(self.server_url_args)
        self.generic_args.extend(self.bearer_token_arg)
        sys.argv.extend(self.generic_args)
        sys.argv.extend(setup_args)
        cli.main()

        args, _ = MockCosRegistrationAgent.call_args
        self.assertEqual(len(args), 3)
        self.assertEqual(args[0], self.server_url)
        self.assertEqual(args[1], self.robot_uid)
        self.assertEqual(str(args[2]), self.bearer_token_file)

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
    def test_update_tls_certificate_when_not_signed(
        self, mock_get_machine_ip, MockCosRegistrationAgent
    ):
        """Test that update requests a new certificate when none is signed."""
        mock_cos_registration_agent = MockCosRegistrationAgent.return_value
        mock_cos_registration_agent.is_device_certificate_signed.return_value = (
            False
        )
        self.robot_ip = "4.3.2.1"
        mock_get_machine_ip.return_value = self.robot_ip
        update_args = ["update"]
        update_args.extend(self.robot_uid_args)
        update_args.extend(self.server_url_args)
        update_args.extend(["--generate-device-tls-certificate"])
        sys.argv.extend(self.generic_args)
        sys.argv.extend(update_args)
        cli.main()

        mock_cos_registration_agent.is_device_certificate_signed.assert_called_once()
        mock_cos_registration_agent.request_device_tls_certificate.assert_called()
        mock_cos_registration_agent.poll_for_certificate.assert_called()

    @patch("cos_registration_agent.cli.CosRegistrationAgent")
    @patch("cos_registration_agent.cli.get_machine_ip_address")
    def test_update_tls_certificate_when_already_signed(
        self, mock_get_machine_ip, MockCosRegistrationAgent
    ):
        """Test that update skips certificate request when already signed."""
        mock_cos_registration_agent = MockCosRegistrationAgent.return_value
        mock_cos_registration_agent.is_device_certificate_signed.return_value = (
            True
        )
        self.robot_ip = "4.3.2.1"
        mock_get_machine_ip.return_value = self.robot_ip
        update_args = ["update"]
        update_args.extend(self.robot_uid_args)
        update_args.extend(self.server_url_args)
        update_args.extend(["--generate-device-tls-certificate"])
        sys.argv.extend(self.generic_args)
        sys.argv.extend(update_args)
        cli.main()

        mock_cos_registration_agent.is_device_certificate_signed.assert_called_once()
        mock_cos_registration_agent.request_device_tls_certificate.assert_not_called()
        mock_cos_registration_agent.poll_for_certificate.assert_not_called()

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
