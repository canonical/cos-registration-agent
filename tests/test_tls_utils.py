import unittest
from unittest.mock import patch, MagicMock
import os

from cos_registration_agent.tls_utils import save_device_tls_certs


class TestSaveDeviceTLSCerts(unittest.TestCase):
    def setUp(self):
        self.cert = "cert"
        self.key = "key"
        self.certs_dir = "dir"

    @patch("os.makedirs")
    @patch("cos_registration_agent.tls_utils.write_data")
    def test_save_cert_success(self, mock_write_data, mock_makedirs):

        save_device_tls_certs(self.cert, self.key, self.certs_dir)

        mock_makedirs.assert_called_once_with(self.certs_dir, exist_ok=True)
        mock_write_data.assert_any_call(
            self.cert, "device.crt", self.certs_dir
        )
        mock_write_data.assert_any_call(self.key, "device.key", self.certs_dir)

    def test_missing_cert_or_key_raises(self):
        with self.assertRaises(RuntimeError):
            save_device_tls_certs(None, self.key, self.certs_dir)
        with self.assertRaises(RuntimeError):
            save_device_tls_certs(self.cert, None, self.certs_dir)

    @patch(
        "os.makedirs",
        side_effect=OSError("Permission denied"),
    )
    def test_oserror_raised(self, mock_makedirs):
        with self.assertRaises(OSError):
            save_device_tls_certs(self.cert, self.key, self.certs_dir)
