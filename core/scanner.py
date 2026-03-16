import os
from core.detector import detect_file_type

def scan_file(file_path):
    real_type = detect_file_type(file_path)
    extension = os.path.splitext(file_path)[1].replace(".", "").lower()

    print("File:", file_path)
    print("Extension:", extension)
    print("Actual Type:", real_type)

    if extension != real_type:
        print("⚠ WARNING: File extension mismatch detected!")