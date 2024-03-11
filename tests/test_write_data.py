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

        #self.mock_os_get.assert_called_once_with(self.folder)
        mock_open.assert_called_once_with('folder/test.txt', 'w')
        handle = mock_open.return_value.__enter__.return_value
        handle.write.assert_called_once_with(self.data)
        self.assertTrue(handle.write.called)

    @patch('cos_registration_agent.write_data.open', new_callable=MagicMock)
    def test_write_data_success_with_env_var(self, mock_open):
        folder = "$SNAP_COMMON/folder"
        mock_os_get_patcher = patch('cos_registration_agent.write_data.os.environ.get')
        mock_os_get = mock_os_get_patcher.start()
        mock_os_get.return_value = '/var/snap/common/'
        write_data(self.data, self.filename, folder)

        mock_open.assert_called_once_with('/var/snap/common/folder/test.txt', 'w')
        handle = mock_open.return_value.__enter__.return_value
        handle.write.assert_called_once_with(self.data)
        self.assertTrue(handle.write.called)
