import argparse
import os
import sys

# Ensure imports work from anywhere
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from core.scanner import scan_file

parser = argparse.ArgumentParser(description="File Type Identifier Tool")
parser.add_argument("file", nargs="?", help="File to scan (Optional if using --gui)")
parser.add_argument("--gui", action="store_true", help="Launch the Drag & Drop Graphical User Interface")

args = parser.parse_args()

if args.gui:
    from PyQt6.QtWidgets import QApplication
    from gui.app import AppWindow
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec())
    
if not args.file:
    parser.print_help()
    sys.exit(1)

if not os.path.exists(args.file):
    print("❌ File not found:", args.file)
else:
    scan_file(args.file)