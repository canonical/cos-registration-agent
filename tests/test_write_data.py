import unittest
from unittest.mock import patch, MagicMock

from cos_registration_agent.write_data import write_data


class TestWriteData(unittest.TestCase):
    def setUp(self):
        self.data = "test data"
        self.filename = "test.txt"
        self.folder = "folder"

    @patch('cos_registration_agent.write_data.open', new_callable=MagicMock)
    def test_write_data_success(self, mock_open):
        write_data(self.data, self.filename, self.folder)

        mock_open.assert_called_once_with('folder/test.txt', 'w')
        handle = mock_open.return_value.__enter__.return_value
        handle.write.assert_called_once_with(self.data)
        self.assertTrue(handle.write.called)

    @patch('cos_registration_agent.write_data.open', side_effect=OSError)
    def test_write_data_os_error(self, mock_open):
        with self.assertRaises(OSError):
            write_data(self.data, self.filename, self.folder)

        mock_open.assert_called_once_with('folder/test.txt', 'w')
