import json
import os

def load_magic_db():
    db_path = os.path.join(os.path.dirname(__file__), "magic_db.json")
    with open(db_path) as f:
        return json.load(f)


def read_file_header(file_path, bytes_to_read=8):
    with open(file_path, "rb") as f:
        header = f.read(bytes_to_read)
    return header.hex().upper()


def detect_file_type(file_path):
    magic_db = load_magic_db()
    header = read_file_header(file_path)

    for filetype, signature in magic_db.items():
        if header.startswith(signature):
            return filetype

    return "Unknown"