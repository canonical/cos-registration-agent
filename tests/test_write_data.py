import unittest
from unittest.mock import patch, MagicMock

from cos_registration_agent.write_data import write_data


class TestWriteData(unittest.TestCase):
    def setUp(self):
        self.mock_os_get_patcher = patch('cos_registration_agent.write_data.os.environ.get')
        self.mock_os_get = self.mock_os_get_patcher.start()
        self.mock_os_get.return_value = '/testfolder'

        self.data = "test data"
        self.filename = "test.txt"
        self.folder = "folder"

    def tearDown(self):
        self.mock_os_get_patcher.stop()

    @patch('cos_registration_agent.write_data.open', new_callable=MagicMock)
    def test_write_data_success(self, mock_open):

        result = write_data(self.data, self.filename, self.folder)

        self.mock_os_get.assert_called_once_with(self.folder)
        mock_open.assert_called_once_with('/testfolder/test.txt', 'w')
        handle = mock_open.return_value.__enter__.return_value
        handle.write.assert_called_once_with(self.data)
        self.assertTrue(result)

    @patch('cos_registration_agent.write_data.open', side_effect=OSError)
    def test_write_data_os_error(self, mock_open):

        with self.assertRaises(OSError):
            write_data(self.data, self.filename, self.folder)

        self.mock_os_get.assert_called_once_with(self.folder)
        mock_open.assert_called_once_with('/testfolder/test.txt', 'w')

    @patch('cos_registration_agent.write_data.os.environ.get', side_effect=KeyError)
    def test_write_data_key_error(self, mock_os_get):
        with self.assertRaises(KeyError):
            write_data(self.data, self.filename, self.folder)

        mock_os_get.assert_called_once_with(self.folder)
