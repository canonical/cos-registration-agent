import unittest
from unittest.mock import patch, MagicMock
from cos_registration_agent.machine_ip_address import get_machine_ip_address


class TestGetMachineIPAddress(unittest.TestCase):
    @patch("cos_registration_agent.machine_ip_address.socket.gethostbyname")
    @patch("cos_registration_agent.machine_ip_address.IPRoute")
    def test_get_machine_ip_address_dns(
        self, mock_iproute, mock_gethostbyname
    ):
        test_url = "http://test.com"
        mock_gethostbyname.return_value = "1.2.3.4"

        # Mock IPRoute behavior to return mock IP
        mock_ipr_instance = MagicMock()
        mock_iproute.return_value.__enter__.return_value = mock_ipr_instance
        mock_ipr_instance.route.return_value = [
            {"attrs": [("RTA_PREFSRC", "1.1.1.1")]}
        ]

        result = get_machine_ip_address(test_url)
        self.assertEqual(result, "1.1.1.1")

        mock_gethostbyname.assert_called_once_with("test.com")
        mock_ipr_instance.route.assert_called_once_with("get", dst="1.2.3.4")

    @patch("cos_registration_agent.machine_ip_address.socket.gethostbyname")
    @patch("cos_registration_agent.machine_ip_address.IPRoute")
    def test_get_machine_ip_address_with_ip(
        self, mock_iproute, mock_gethostbyname
    ):
        test_url = "http://1.2.3.4/test"
        mock_gethostbyname.return_value = "1.2.3.4"

        # Mock IPRoute behavior to return mock IP
        mock_ipr_instance = MagicMock()
        mock_iproute.return_value.__enter__.return_value = mock_ipr_instance
        mock_ipr_instance.route.return_value = [
            {"attrs": [("RTA_PREFSRC", "1.1.1.1")]}
        ]

        result = get_machine_ip_address(test_url)
        self.assertEqual(result, "1.1.1.1")

        mock_gethostbyname.assert_called_once_with("1.2.3.4")
        mock_ipr_instance.route.assert_called_once_with("get", dst="1.2.3.4")


if __name__ == "__main__":
    unittest.main()
