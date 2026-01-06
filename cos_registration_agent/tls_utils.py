"""Module to handle device TLS certificates."""

import logging
import os

from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)


def save_device_tls_certs(cert: str, key: str, certs_dir: str) -> None:
    """Save TLS certificate and key to folder.

    Args:
        cert: the certificate as string
        key: the private key as string
        certs_dir (str): Directory to save the certs into.
    """
    if not cert or not key:
        raise RuntimeError("No TLS certificate or key found in response/")

    try:
        os.makedirs(certs_dir, exist_ok=True)
        write_data(cert, "device.crt", certs_dir)
        write_data(key, "device.key", certs_dir)
        logger.info(f"TLS certs saved to {certs_dir}")
    except OSError as e:
        logger.error(f"Error saving TLS certs: {e}")
        raise e
