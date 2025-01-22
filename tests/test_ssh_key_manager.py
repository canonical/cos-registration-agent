import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

from cos_registration_agent.ssh_key_manager import SSHKeysManager


class TestWriteData(unittest.TestCase):
    def test_generate_ssh_keypair(self):
        private_key, public_key = SSHKeysManager().generate_ssh_keypair()
        rsa_private_key = serialization.load_pem_private_key(
            private_key.encode("utf-8"), password=None
        )

        public_key_bytes_base64 = public_key.encode("utf-8")

        rsa_public_key = serialization.load_ssh_public_key(
            public_key_bytes_base64, backend=default_backend()
        )

        secret_message = "this is a secret"

        cyphered_message = rsa_public_key.encrypt(
            secret_message.encode("utf-8"), padding.PKCS1v15()
        )

        decyphered_message = rsa_private_key.decrypt(
            cyphered_message, padding.PKCS1v15()
        )

        self.assertEqual(decyphered_message.decode("utf-8"), secret_message)
