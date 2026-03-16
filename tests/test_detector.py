import unittest
import os
import shutil
from core.detector import detect_file_type, load_magic_db
from core.scanner import scan_file

class TestDetector(unittest.TestCase):
    def setUp(self):
        # Create a mock magic db for testing
        self.magic_db = load_magic_db()
        self.sample_dir = os.path.join(os.path.dirname(__file__), "..", "sample_files")
        
        if not os.path.exists(self.sample_dir):
            os.makedirs(self.sample_dir)
            
        # Create a fake PNG file
        self.real_png = os.path.join(self.sample_dir, "real_image.png")
        with open(self.real_png, "wb") as f:
            f.write(bytes.fromhex("89504E470D0A1A0A0000000D49484452"))
            
        # Create a fake JPG file that is actually an EXE
        self.fake_jpg = os.path.join(self.sample_dir, "fake_image.jpg")
        with open(self.fake_jpg, "wb") as f:
            f.write(bytes.fromhex("4D5A90000300000004000000FFFF0000"))
            
        # Create an unknown file
        self.unknown_file = os.path.join(self.sample_dir, "unknown.txt")
        with open(self.unknown_file, "wb") as f:
            f.write(bytes.fromhex("0000000000000000"))

    def test_detect_real_png(self):
        file_type = detect_file_type(self.real_png)
        self.assertEqual(file_type, "png")

    def test_detect_fake_jpg(self):
        file_type = detect_file_type(self.fake_jpg)
        self.assertEqual(file_type, "exe")
        
    def test_detect_unknown(self):
        file_type = detect_file_type(self.unknown_file)
        self.assertEqual(file_type, "Unknown")

if __name__ == '__main__':
    unittest.main()
