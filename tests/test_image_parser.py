import unittest
from unittest.mock import MagicMock, patch
from src.core.image_parser import ImageParser

class TestImageParser(unittest.TestCase):

    @patch('pytsk3.Img_Info')
    @patch('pytsk3.FS_Info')
    def test_image_parser_init(self, mock_fs_info, mock_img_info):
        # Setup mock
        mock_img_instance = MagicMock()
        mock_img_info.return_value = mock_img_instance
        
        mock_fs_instance = MagicMock()
        mock_fs_info.return_value = mock_fs_instance
        
        # Instantiate
        parser = ImageParser("dummy.img")
        
        # Assertions
        mock_img_info.assert_called_with("dummy.img")
        mock_fs_info.assert_called_with(mock_img_instance, offset=0)
        self.assertEqual(parser.img_info, mock_img_instance)
        self.assertEqual(parser.fs_info, mock_fs_instance)

    @patch('pytsk3.Img_Info')
    @patch('pytsk3.FS_Info')
    def test_list_directory(self, mock_fs_info, mock_img_info):
        # Setup mocks
        mock_fs_instance = MagicMock()
        mock_fs_info.return_value = mock_fs_instance
        
        mock_dir = MagicMock()
        mock_fs_instance.open_dir.return_value = mock_dir
        
        # Mock directory entries
        mock_entry = MagicMock()
        mock_entry.info.name.name = b"test_file.txt"
        mock_entry.info.meta.type = 1 # pytsk3.TSK_FS_META_TYPE_REG (Reg file)
        mock_entry.info.meta.size = 100
        
        mock_dir.__iter__.return_value = [mock_entry]
        
        parser = ImageParser("dummy.img")
        results = list(parser.list_directory("/"))
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "test_file.txt")
        self.assertEqual(results[0]["type"], "File")
        self.assertEqual(results[0]["size"], 100)

if __name__ == '__main__':
    unittest.main()
