"""Module to save device TLS certificates."""

import logging
import os

from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)


def save_device_tls_certs(cert_file, key_file, certs_dir):
    """Generate SSH keys and write them to a folder.

    Args:
        private_ssh_key (int): The private ssh key.
        public_ssh_key (int): The public ssh key.
        folder (str): Folder to save the keys.
    """
    try:
        os.makedirs(certs_dir, exist_ok=True)
        write_data(cert_file, "device.crt", certs_dir)
        write_data(key_file, "device.key", certs_dir)
    except OSError as e:
        logger.error(f"Error setting up device TLS certs: {e}")
        raise e
