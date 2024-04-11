"""Class to manage device SSH keys."""

import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)


class SSHKeysManager:
    """Class to manage device SSH keys."""

    def generate_ssh_keypair(self, public_exponent=65537, key_size=2048):
        """Generate SSH keypair.

        Returns:
            tuple: private key and public key.

        """
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=public_exponent,
            key_size=key_size,
        )

        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        public_key = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )

        private_key = private_key.decode("utf-8")
        public_key = public_key.decode("utf-8")
        return private_key, public_key

    def write_keys(self, private_ssh_key, public_ssh_key, folder):
        """Generate SSH keys and write them to a folder.

        Args:
            private_ssh_key (int): The private ssh key.
            public_ssh_key (int): The public ssh key.
            folder (str): Folder to save the keys.
        """
        try:
            write_data(private_ssh_key, "device_rsa_key", folder)
            write_data(public_ssh_key, "device_rsa_key.pub", folder)
        except Exception as e:
            logger.error(f"Error setting up SSH keys: {e}")
            raise e
