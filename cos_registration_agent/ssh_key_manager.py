import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cos_registration_agent.write_data import write_data

logger = logging.getLogger(__name__)

class SSHKeysManager:
    """Class to manage device SSH keys."""
    
    def _generate_ssh_keypair(self, public_exponent=65537, key_size=2048):
        """
        Generate SSH keypair.

        Returns:
            tuple: Private key and public key.
        """
        key = rsa.generate_private_key(backend=default_backend(),
                                               public_exponent=public_exponent,
                                               key_size=key_size)

        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        public_key = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH
        )

        private_key = private_key.decode('utf-8')
        public_key = public_key.decode('utf-8')
        return private_key, public_key

    def setup(self, public_exponent=65537, key_size=2048, folder='SNAP_COMMON'):
        """
        Generate SSH keys and write them to a folder

        Args:
            public_exponent (int): The public exponent of the new key.
            key_size (int): The length of the modulus in bits. 
            folder (str): Folder to save the keys.
        """
        private_key, public_key = self._generate_ssh_keypair(public_exponent, key_size)
        try:
            write_data(private_key, "device_rsa_key", folder)
            write_data(public_key, "device_rsa_key.pub", folder)
        except Exception as e:
            logger.error(f"Error setting up SSH keys: {e}")
            raise e
