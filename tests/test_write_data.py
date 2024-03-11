import unittest
from unittest.mock import patch, MagicMock

from cos_registration_agent.write_data import write_data


class TestWriteData(unittest.TestCase):
    def setUp(self):
        self.mock_os_get_patcher = patch('cos_registration_agent.write_data.os.environ.get')
        self.mock_os_get = self.mock_os_get_patcher.start()
        self.mock_os_get.return_value = '/var/snap/common/'

        self.data = "test data"
        self.filename = "test.txt"
        self.snap_folder_env = "snap_common"
        self.folder = "rob-cos-shared-data"
        self.addCleanup(self.mock_os_get_patcher.stop)


    @patch('cos_registration_agent.write_data.open', new_callable=MagicMock)
    def test_write_data_success(self, mock_open):
        write_data(self.data, self.filename, self.snap_folder_env, self.folder)

        self.mock_os_get.assert_called_once_with(self.snap_folder_env)
        mock_open.assert_called_once_with('/var/snap/common/rob-cos-shared-data/test.txt', 'w')
        handle = mock_open.return_value.__enter__.return_value
        handle.write.assert_called_once_with(self.data)
        self.assertTrue(handle.write.called)

    @patch('cos_registration_agent.write_data.open', side_effect=OSError)
    def test_write_data_os_error(self, mock_open):
        with self.assertRaises(OSError):
            write_data(self.data, self.filename, self.snap_folder_env, self.folder)

        self.mock_os_get.assert_called_once_with(self.snap_folder_env)
        mock_open.assert_called_once_with('/var/snap/common/rob-cos-shared-data/test.txt', 'w')

    @patch('cos_registration_agent.write_data.os.environ.get', side_effect=KeyError)
    def test_write_data_key_error(self, mock_os_get):
        with self.assertRaises(KeyError):
            write_data(self.data, self.filename, self.snap_folder_env, self.folder)

        mock_os_get.assert_called_once_with(self.snap_folder_env)
