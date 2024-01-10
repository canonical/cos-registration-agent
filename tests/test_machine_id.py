import unittest

from cos_registration_agent.machine_id import get_machine_id


class TestGrafana(unittest.TestCase):
    def test_machine_id_open_file(self):
        machine_id = get_machine_id()

        for char in machine_id:
            self.assertRegex(char, "[a-zA-Z0-9]")
