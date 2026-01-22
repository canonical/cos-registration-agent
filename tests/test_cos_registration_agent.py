import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import responses
import json
import yaml


from cos_registration_agent.cos_registration_agent import (
    API_VERSION,
    CosRegistrationAgent,
)


class TestCosRegistrationAgent(unittest.TestCase):

    def setUp(self):
        """Creates ``RequestsMock`` instance and starts it."""
        self.r_mock = responses.RequestsMock(
            assert_all_requests_are_fired=True
        )
        self.r_mock.start()

        self.server_name = "my-rob-cos-server"

        self.server_url = "http://" + self.server_name

        self.device_uid = "my-robot"

        self.bearer_token = "my-secret-token"

        # optionally some default responses could be registered
        self.r_mock.get(
            self.server_url + "/" + API_VERSION + "health/", status=200
        )

    def tearDown(self):
        """Stops and resets RequestsMock instance."""
        self.r_mock.stop()
        self.r_mock.reset()

    def test_server_health_ok(self):
        CosRegistrationAgent(self.server_url, "my-robot")

    def test_server_health_fail(self):
        self.r_mock.get(
            self.server_url + "/" + API_VERSION + "health/", status=401
        )

        # necessary due to the setUp
        CosRegistrationAgent(self.server_url, "my-robot")

        self.assertRaises(
            RuntimeError, CosRegistrationAgent, self.server_url, "my-robot"
        )

    def test_register_device(self):
        device_ip = "1.2.3.4"
        device_public_ssh_key = "my public key"
        device_grafana_dashboards = ["g_dashboard1", "g_dashboard2"]
        device_foxglove_dashboards = ["f_dashboard1", "f_dashboard2"]
        device_loki_rules_files = ["l_alert_file_1"]
        device_prometheus_rules_files = ["p_alert_file_1"]

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        def request_callback(request):
            payload = json.loads(request.body)
            self.assertEqual(payload["uid"], self.device_uid)
            self.assertEqual(payload["address"], device_ip)
            self.assertEqual(payload["public_ssh_key"], device_public_ssh_key)
            self.assertEqual(
                payload["grafana_dashboards"], device_grafana_dashboards
            )
            self.assertEqual(
                payload["foxglove_dashboards"], device_foxglove_dashboards
            )
            self.assertEqual(
                payload["loki_rules_files"], device_loki_rules_files
            )
            self.assertEqual(
                payload["prometheus_rules_files"],
                device_prometheus_rules_files,
            )

            headers = {"content-type": "application/json"}
            return (201, headers, None)

        self.r_mock.add_callback(
            responses.POST,
            self.server_url + "/" + API_VERSION + "devices/",
            callback=request_callback,
            content_type="application/json",
        )

        agent.register_device(
            address=device_ip,
            public_ssh_key=device_public_ssh_key,
            grafana_dashboards=device_grafana_dashboards,
            foxglove_dashboards=device_foxglove_dashboards,
            loki_rules_files=device_loki_rules_files,
            prometheus_rules_files=device_prometheus_rules_files,
        )

    def test_fail_register_device(self):

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        self.r_mock.post(
            self.server_url + "/" + API_VERSION + "devices/",
            json.dumps({"error": "the address is missing"}),
            status=400,
            headers={"content-type": "application/json"},
        )

        self.assertRaises(
            SystemError,
            agent.register_device,
        )

    def test_delete_device(self):

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        self.r_mock.delete(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/",
            status=204,
        )

        agent.delete_device()

    def test_patch_device(self):
        device_ip = "1.2.3.4"

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/",
            json.dumps({"address": device_ip}),
            status=200,
            headers={"content-type": "application/json"},
        )

        device_ip = "4.3.2.1"

        def request_callback(request):
            payload = json.loads(request.body)
            self.assertEqual(payload["address"], device_ip)

            headers = {"content-type": "application/json"}
            return (200, headers, None)

        self.r_mock.add_callback(
            responses.PATCH,
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/",
            callback=request_callback,
            content_type="application/json",
        )

        agent.patch_device({"address": device_ip})

    @patch(
        "builtins.open",
        new_callable=MagicMock,
    )
    @patch("pathlib.Path.is_file", return_value=True)
    def test_add_dashboards(self, mock_open, mock_is_file):

        grafana_dashboard_name = "my-dashboard"
        grafana_dashboard = """
        {"dashboard": "content"}
        """

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        with patch("json.load", return_value=grafana_dashboard):
            with patch(
                "pathlib.Path.iterdir",
                return_value=[Path(grafana_dashboard_name + ".json")],
            ):
                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/"
                    + grafana_dashboard_name
                    + "/",
                    None,
                    status=404,
                    headers={"content-type": "text/html;charset=utf-8"},
                )

                def request_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["uid"], grafana_dashboard_name)
                    self.assertEqual(payload["dashboard"], grafana_dashboard)

                    headers = {"content-type": "application/json"}
                    return (201, headers, None)

                self.r_mock.add_callback(
                    responses.POST,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/",
                    callback=request_callback,
                    content_type="application/json",
                )

                agent.patch_dashboards("path_to_my_dashboard", "grafana")

    @patch(
        "builtins.open",
        new_callable=MagicMock,
    )
    @patch("pathlib.Path.is_file", return_value=True)
    def test_patch_dashboards(self, mock_open, mock_is_file):

        grafana_dashboard_name = "my-dashboard"
        grafana_dashboard = """
        {"dashboard": "content"}
        """

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        with patch(
            "json.load", return_value=grafana_dashboard
        ) as json_load_mock:
            with patch(
                "pathlib.Path.iterdir",
                return_value=[Path(grafana_dashboard_name + ".json")],
            ):
                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/"
                    + grafana_dashboard_name
                    + "/",
                    None,
                    status=404,
                    headers={"content-type": "text/html;charset=utf-8"},
                )

                def request_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["uid"], grafana_dashboard_name)
                    self.assertEqual(payload["dashboard"], grafana_dashboard)

                    headers = {"content-type": "application/json"}
                    return (201, headers, None)

                self.r_mock.add_callback(
                    responses.POST,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/",
                    callback=request_callback,
                    content_type="application/json",
                )

                agent.patch_dashboards("path_to_my_dashboard", "grafana")

                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/"
                    + grafana_dashboard_name
                    + "/",
                    grafana_dashboard,
                    status=200,
                    headers={
                        "content-type": "application/json; Content-Disposition attachment; filename=layout_uid.json"
                    },
                )

                grafana_dashboard = """
                {"dashboard": "new content"}
                """

                def patch_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["dashboard"], grafana_dashboard)

                    headers = {"content-type": "application/json"}
                    return (200, headers, grafana_dashboard)

                self.r_mock.add_callback(
                    responses.PATCH,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/grafana/dashboards/"
                    + grafana_dashboard_name
                    + "/",
                    callback=patch_callback,
                    content_type="application/json",
                )

                json_load_mock.return_value = grafana_dashboard
                agent.patch_dashboards("path_to_my_dashboard", "grafana")

    @patch(
        "builtins.open",
        new_callable=MagicMock,
    )
    @patch("pathlib.Path.is_file", return_value=True)
    def test_add_rule_file(self, mock_open, mock_is_file):

        loki_rule_file_name = "my-rule"
        loki_rule_file = """
        groups:
          - name: my_rule
        """
        loki_rule_file_dict = yaml.safe_load(loki_rule_file)
        # put the content in the yaml dump format
        loki_rule_file = yaml.dump(loki_rule_file_dict)

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        with patch("yaml.safe_load", return_value=loki_rule_file_dict):
            with patch(
                "pathlib.Path.iterdir",
                return_value=[Path(loki_rule_file_name + ".rules")],
            ):
                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/"
                    + loki_rule_file_name
                    + "/",
                    None,
                    status=404,
                    headers={"content-type": "text/html;charset=utf-8"},
                )

                def request_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["uid"], loki_rule_file_name)
                    self.assertEqual(payload["rules"], loki_rule_file)

                    headers = {"content-type": "application/json"}
                    return (201, headers, None)

                self.r_mock.add_callback(
                    responses.POST,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/",
                    callback=request_callback,
                    content_type="application/json",
                )

                agent.patch_rule_files("path_to_my_rule_file", "loki")

    @patch(
        "builtins.open",
        new_callable=MagicMock,
    )
    @patch("pathlib.Path.is_file", return_value=True)
    def test_patch_rule_file(self, mock_open, mock_is_file):

        loki_rule_file_name = "my-rule"
        loki_rule_file = """
        groups:
          - name: my_rule
        """
        loki_rule_file_dict = yaml.safe_load(loki_rule_file)
        # put the content in the yaml dump format
        loki_rule_file = yaml.dump(loki_rule_file_dict)

        agent = CosRegistrationAgent(self.server_url, self.device_uid)

        with patch(
            "yaml.safe_load", return_value=loki_rule_file_dict
        ) as yaml_safe_load_mock:
            with patch(
                "pathlib.Path.iterdir",
                return_value=[Path(loki_rule_file_name + ".rules")],
            ):
                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/"
                    + loki_rule_file_name
                    + "/",
                    None,
                    status=404,
                    headers={"content-type": "text/html;charset=utf-8"},
                )

                def request_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["uid"], loki_rule_file_name)
                    self.assertEqual(payload["rules"], loki_rule_file)

                    headers = {"content-type": "application/json"}
                    return (201, headers, None)

                self.r_mock.add_callback(
                    responses.POST,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/",
                    callback=request_callback,
                    content_type="application/json",
                )

                agent.patch_rule_files("path_to_my_rule_file", "loki")

                self.r_mock.get(
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/"
                    + loki_rule_file_name
                    + "/",
                    json={
                        "uid": loki_rule_file_name,
                        "rules": loki_rule_file,
                    },
                    status=200,
                    headers={"content-type": "application/json"},
                )

                loki_rule_file = """
                groups:
                  - name: new_my_rule
                """
                loki_rule_file_dict = yaml.safe_load(loki_rule_file)
                # put the content in the yaml dump format
                loki_rule_file = yaml.dump(loki_rule_file_dict)

                def patch_callback(request):
                    payload = json.loads(request.body)
                    self.assertEqual(payload["rules"], loki_rule_file)

                    headers = {"content-type": "application/json"}
                    return (200, headers, None)

                self.r_mock.add_callback(
                    responses.PATCH,
                    self.server_url
                    + "/"
                    + API_VERSION
                    + "applications/loki/alert_rules/"
                    + loki_rule_file_name
                    + "/",
                    callback=patch_callback,
                    content_type="application/json",
                )

                yaml_safe_load_mock.return_value = loki_rule_file_dict
                agent.patch_rule_files("path_to_my_rule_file", "loki")

    @patch("pathlib.Path.is_file", return_value=True)
    def test_bearer_token_file(self, mock_is_file):
        """Test that CosRegistrationAgent reads the bearer token from file and passes it to the client."""
        with patch("pathlib.Path.read_text", return_value=self.bearer_token):
            agent = CosRegistrationAgent(
                self.server_url,
                self.device_uid,
                token_file=Path("/fake/token/file"),
            )
            self.assertIn("Authorization", agent.cos_client.headers)
            self.assertEqual(
                agent.cos_client.headers["Authorization"],
                "bearer my-secret-token",
            )

    @patch(
        "cos_registration_agent.cos_registration_agent.generate_private_key"
    )
    @patch("cos_registration_agent.cos_registration_agent.generate_csr")
    @patch("cos_registration_agent.cos_registration_agent.store_private_key")
    def test_request_device_tls_certificate_success(
        self,
        mock_store_private_key,
        mock_generate_csr,
        mock_generate_private_key,
    ):
        """Test successful CSR submission with immediate private key storage."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        mock_private_key = MagicMock()
        mock_generate_private_key.return_value = mock_private_key
        mock_generate_csr.return_value = "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"

        certs_dir = "/test/certs"
        device_ip = "192.168.1.100"

        self.r_mock.post(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            status=202,
        )

        result = agent.request_device_tls_certificate(device_ip)

        self.assertTrue(result)
        mock_generate_private_key.assert_called_once()
        mock_store_private_key.assert_called_once_with(
            mock_private_key, certs_dir
        )
        mock_generate_csr.assert_called_once_with(
            mock_private_key,
            common_name=self.device_uid,
            device_ip=device_ip,
        )
        self.assertEqual(agent.certs_dir, certs_dir)

    @patch(
        "cos_registration_agent.cos_registration_agent.generate_private_key"
    )
    @patch("cos_registration_agent.cos_registration_agent.generate_csr")
    @patch("cos_registration_agent.cos_registration_agent.store_private_key")
    def test_request_device_tls_certificate_failure(
        self,
        mock_store_private_key,
        mock_generate_csr,
        mock_generate_private_key,
    ):
        """Test failed CSR submission with non-202 status."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        mock_private_key = MagicMock()
        mock_generate_private_key.return_value = mock_private_key
        mock_generate_csr.return_value = "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"

        device_ip = "192.168.1.100"

        self.r_mock.post(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            status=400,
            body="Bad request",
        )

        result = agent.request_device_tls_certificate(device_ip)

        self.assertFalse(result)

    @patch("cos_registration_agent.cos_registration_agent.store_certificate")
    @patch("time.sleep", return_value=None)  # Speed up the test
    def test_poll_for_certificate_signed(
        self, mock_sleep, mock_store_certificate
    ):
        """Test successful certificate polling when status is 'signed'."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        signed_cert = (
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        )

        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            json={"status": "signed", "chain": signed_cert},
            status=200,
        )

        result = agent.poll_for_certificate(timeout_seconds=2)

        self.assertTrue(result)
        mock_store_certificate.assert_called_once_with(
            signed_cert, "/test/certs"
        )

    @patch("time.sleep", return_value=None)
    def test_poll_for_certificate_denied(self, mock_sleep):
        """Test certificate polling when CSR is denied."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            json={"status": "denied"},
            status=200,
        )

        with self.assertRaises(PermissionError) as context:
            agent.poll_for_certificate(timeout_seconds=2)

        self.assertIn("denied by the server", str(context.exception))

    @patch("time.sleep", return_value=None)
    def test_poll_for_certificate_not_found(self, mock_sleep):
        """Test certificate polling when device/CSR is not found."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            status=404,
        )

        with self.assertRaises(FileNotFoundError) as context:
            agent.poll_for_certificate(timeout_seconds=2)

        self.assertIn(
            "Certificate for device not found", str(context.exception)
        )

    @patch("cos_registration_agent.cos_registration_agent.store_certificate")
    @patch("time.sleep", return_value=None)
    def test_poll_for_certificate_timeout(
        self, mock_sleep, mock_store_certificate
    ):
        """Test certificate polling timeout."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        # Mock time to simulate timeout
        call_count = [0]

        def mock_time_fn():
            call_count[0] += 1
            return 0 if call_count[0] == 1 else 601

        with patch(
            "cos_registration_agent.cos_registration_agent.time.time",
            side_effect=mock_time_fn,
        ):
            with self.assertRaises(TimeoutError) as context:
                agent.poll_for_certificate(timeout_seconds=2)

            self.assertIn(
                "Timeout: failed to obtain signed certificate",
                str(context.exception),
            )
            mock_store_certificate.assert_not_called()

    @patch("cos_registration_agent.cos_registration_agent.store_certificate")
    @patch("time.sleep", return_value=None)
    def test_poll_for_certificate_pending_then_signed(
        self, mock_sleep, mock_store_certificate
    ):
        """Test certificate polling that transitions from pending to signed."""
        agent = CosRegistrationAgent(
            self.server_url, self.device_uid, certs_dir="/test/certs"
        )

        signed_cert = (
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        )
        # First call returns pending, second returns signed
        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            json={"status": "pending"},
            status=200,
        )
        self.r_mock.get(
            self.server_url
            + "/"
            + API_VERSION
            + "devices/"
            + self.device_uid
            + "/certificate/",
            json={"status": "signed", "chain": signed_cert},
            status=200,
        )

        result = agent.poll_for_certificate(timeout_seconds=2)

        self.assertTrue(result)
        mock_sleep.assert_called()
        mock_store_certificate.assert_called_once_with(
            signed_cert, "/test/certs"
        )
