import unittest
from unittest.mock import patch, MagicMock, Mock
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from cos_registration_agent.tls_utils import (
    generate_private_key,
    generate_csr,
    store_certificate,
    store_private_key,
)


class TestGeneratePrivateKey(unittest.TestCase):
    def test_generates_rsa_key(self):
        """Test that generate_private_key returns an RSA private key."""
        private_key = generate_private_key()

        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertEqual(private_key.key_size, 4096)


class TestGenerateCSR(unittest.TestCase):
    def test_generates_valid_csr(self):
        """Test that generate_csr creates a valid CSR with correct CN."""
        private_key = generate_private_key()
        common_name = "test-device-id"
        device_ip = "192.168.1.100"

        csr_pem = generate_csr(private_key, common_name, device_ip)

        # Verify it's a PEM-encoded string
        self.assertIsInstance(csr_pem, str)
        self.assertIn("-----BEGIN CERTIFICATE REQUEST-----", csr_pem)
        self.assertIn("-----END CERTIFICATE REQUEST-----", csr_pem)

        # Parse the CSR and verify the CN
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        self.assertEqual(cn.value, common_name)

        # Verify SAN contains the IP address
        import ipaddress

        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        ip_addresses = [
            ip for ip in san_ext.value if isinstance(ip, x509.IPAddress)
        ]
        self.assertEqual(len(ip_addresses), 1)
        self.assertEqual(
            ip_addresses[0].value, ipaddress.ip_address(device_ip)
        )


class TestStorePrivateKey(unittest.TestCase):
    def setUp(self):
        self.private_key = generate_private_key()
        self.certs_dir = "/test/dir"

    @patch("os.makedirs")
    @patch("cos_registration_agent.tls_utils.write_data")
    def test_store_private_key_success(self, mock_write_data, mock_makedirs):
        """Test successful private key storage."""
        store_private_key(self.private_key, self.certs_dir)

        mock_makedirs.assert_called_once_with(self.certs_dir, exist_ok=True)
        mock_write_data.assert_called_once()

        # Verify the private key PEM was written
        call_args = mock_write_data.call_args[0]
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", call_args[0])
        self.assertEqual(call_args[1], "device.key")
        self.assertEqual(call_args[2], self.certs_dir)

    @patch(
        "os.makedirs",
        side_effect=OSError("Permission denied"),
    )
    def test_oserror_raised(self, mock_makedirs):
        """Test that OSError during directory creation is propagated."""
        with self.assertRaises(OSError):
            store_private_key(self.private_key, self.certs_dir)


class TestStoreCertificate(unittest.TestCase):
    def setUp(self):
        self.certificate = (
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        )
        self.certs_dir = "/test/dir"

    @patch("os.makedirs")
    @patch("cos_registration_agent.tls_utils.write_data")
    def test_store_certificate_success(self, mock_write_data, mock_makedirs):
        """Test successful certificate storage."""
        store_certificate(self.certificate, self.certs_dir)

        mock_makedirs.assert_called_once_with(self.certs_dir, exist_ok=True)
        mock_write_data.assert_called_once_with(
            self.certificate, "device.crt", self.certs_dir
        )

    def test_missing_certificate_raises(self):
        """Test that missing certificate raises RuntimeError."""
        with self.assertRaises(RuntimeError):
            store_certificate(None, self.certs_dir)

    @patch(
        "os.makedirs",
        side_effect=OSError("Permission denied"),
    )
    def test_oserror_raised(self, mock_makedirs):
        """Test that OSError during directory creation is propagated."""
        with self.assertRaises(OSError):
            store_certificate(self.certificate, self.certs_dir)
