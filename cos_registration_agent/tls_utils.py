"""Module to handle device TLS certificates."""

import logging
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a 4096-bit RSA private key.

    Returns:
        RSAPrivateKey: Generated private key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    logger.info("Generated 4096-bit RSA private key")
    return private_key


def generate_csr(
    private_key: rsa.RSAPrivateKey, common_name: str, device_ip: str
) -> str:
    """Generate a Certificate Signing Request (CSR).

    Args:
        private_key: The private key to use for signing the CSR.
        common_name: The common name (CN) for the certificate (device ID).
        device_ip: The IP address of the device to include in SAN.

    Returns:
        str: PEM-encoded CSR as a string.
    """
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # Add Subject Alternative Name (SAN) with device IP
    import ipaddress

    san = x509.SubjectAlternativeName(
        [x509.IPAddress(ipaddress.ip_address(device_ip))]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    logger.info(f"Generated CSR for CN={common_name} with SAN IP={device_ip}")
    return csr_pem.decode("utf-8")


def store_private_key(private_key: rsa.RSAPrivateKey, certs_dir: str) -> None:
    """Store the private key to disk.

    Args:
        private_key: The private key to store.
        certs_dir: Directory to save the private key into.
    """
    try:
        os.makedirs(certs_dir, exist_ok=True)

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        write_data(private_key_pem.decode("utf-8"), "device.key", certs_dir)

        logger.info(f"Private key saved to {certs_dir}")
    except OSError as e:
        logger.error(f"Error storing private key: {e}")
        raise e


def store_certificate(certificate: str, certs_dir: str) -> None:
    """Store the signed certificate to disk.

    Args:
        certificate: The signed certificate as PEM string.
        certs_dir: Directory to save the certificate into.
    """
    if not certificate:
        raise RuntimeError("No certificate provided")

    try:
        os.makedirs(certs_dir, exist_ok=True)

        write_data(certificate, "device.crt", certs_dir)

        logger.info(f"Certificate saved to {certs_dir}")
    except OSError as e:
        logger.error(f"Error storing certificate: {e}")
        raise e
