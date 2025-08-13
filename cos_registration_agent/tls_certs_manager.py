"""Module to save device TLS certificates."""

import logging
import os

from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)


def save_device_tls_certs(cert, key, certs_dir):
    """Save device TLS certificate and key to a folder.

    Args:
        cert (str): The certificate.
        key (str): The key.
        folder (str): Folder to save the keys.
    """
    try:
        os.makedirs(certs_dir, exist_ok=True)
        write_data(cert, "device.crt", certs_dir)
        write_data(key, "device.key", certs_dir)
    except OSError as e:
        logger.error(f"Error setting up device TLS certs: {e}")
        raise e
