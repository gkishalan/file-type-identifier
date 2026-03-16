import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, 
    QPushButton, QFileDialog, QMessageBox, QFrame, QHBoxLayout,
    QProgressBar, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette

# Ensure we can import from core
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.detector import detect_file_type
from core.virustotal import scan_file_with_vt, get_api_key, save_api_key
from core.report_generator import generate_pdf_report

class ScanThread(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        
    def run(self):
        try:
            self.progress.emit("Analyzing local file headers...")
            detected_type = detect_file_type(self.file_path)
            extension = os.path.splitext(self.file_path)[1].replace(".", "").lower()
            
            self.progress.emit("Querying VirusTotal...")
            vt_results = scan_file_with_vt(self.file_path, lambda s: self.progress.emit(s))
            
            result = {
                "file_path": self.file_path,
                "detected": detected_type,
                "extension": extension,
                "vt": vt_results
            }
            self.finished.emit(result)
        except Exception as e:
            self.finished.emit({"error": str(e)})

class DropZone(QFrame):
    fileDropped = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setObjectName("dropZone")
        
        layout = QVBoxLayout()
        self.label = QLabel("Drag & Drop File Here\nor Click to Browse")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.label.setStyleSheet("color: #a0a0a0;")
        layout.addWidget(self.label)
        self.setLayout(layout)
        
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
            self.setStyleSheet("#dropZone { border: 3px dashed #4da6ff; background-color: #2a2a35; border-radius: 10px; }")
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setStyleSheet("#dropZone { border: 3px dashed #555; background-color: #1e1e24; border-radius: 10px; }")
            
    def dropEvent(self, event):
        self.setStyleSheet("#dropZone { border: 3px dashed #555; background-color: #1e1e24; border-radius: 10px; }")
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.fileDropped.emit(files[0])
            
    def mousePressEvent(self, event):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file_path:
            self.fileDropped.emit(file_path)

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ultimate File Type & Malware Scanner")
        self.resize(700, 500)
        self.setup_ui()
        self.last_scan_result = None
        
    def setup_ui(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #121216; }
            QLabel { color: white; }
            #dropZone { border: 3px dashed #555; background-color: #1e1e24; border-radius: 10px; margin: 20px; }
            QPushButton { 
                background-color: #4da6ff; color: white; padding: 10px 20px; 
                border-radius: 5px; font-weight: bold; font-size: 14px;
            }
            QPushButton:hover { background-color: #3388dd; }
            QPushButton:disabled { background-color: #555; color: #888; }
            QLineEdit { padding: 8px; border: 1px solid #444; border-radius: 4px; background: #222; color: white;}
            QProgressBar { border: 1px solid #444; border-radius: 4px; text-align: center; color: white; }
            QProgressBar::chunk { background-color: #4da6ff; width: 10px; }
        """)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Header
        title = QLabel("🛡️ Secure File Scanner")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # API Key Settings
        api_layout = QHBoxLayout()
        api_label = QLabel("VirusTotal API Key:")
        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("Enter your VT API Key to enable malware scanning...")
        self.api_input.setEchoMode(QLineEdit.EchoMode.Password)
        if get_api_key():
            self.api_input.setText(get_api_key())
            
        api_save_btn = QPushButton("Save")
        api_save_btn.clicked.connect(self.save_api)
        
        api_layout.addWidget(api_label)
        api_layout.addWidget(self.api_input)
        api_layout.addWidget(api_save_btn)
        layout.addLayout(api_layout)
        
        # Drop Zone
        self.drop_zone = DropZone()
        self.drop_zone.fileDropped.connect(self.start_scan)
        layout.addWidget(self.drop_zone, stretch=1)
        
        # Status / Results
        self.status_label = QLabel("Ready to scan.")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0) # indeterminate
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton("💾 Export PDF Report")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_report)
        btn_layout.addWidget(self.export_btn)
        layout.addLayout(btn_layout)

    def save_api(self):
        save_api_key(self.api_input.text().strip())
        QMessageBox.information(self, "Success", "API Key saved locally!")
        
    def start_scan(self, file_path):
        self.export_btn.setEnabled(False)
        self.status_label.setText(f"Scanning: {os.path.basename(file_path)}...")
        self.progress_bar.show()
        
        self.thread = ScanThread(file_path)
        self.thread.progress.connect(self.update_status)
        self.thread.finished.connect(self.scan_complete)
        self.thread.start()
        
    def update_status(self, msg):
        self.status_label.setText(msg)
        
    def scan_complete(self, results):
        self.progress_bar.hide()
        
        if "error" in results and len(results.keys()) == 1:
            self.status_label.setText(f"❌ Error: {results['error']}")
            return
            
        self.last_scan_result = results
        self.export_btn.setEnabled(True)
        
        ext = results['extension']
        det = results['detected']
        vt = results['vt']
        
        msg = f"<b>Format:</b> .{ext} | <b>True Magic Number:</b> {det}<br>"
        
        if ext == det.lower() or det == "Unknown":
            msg += "<font color='#4caf50'>[PASS] File integrity looks good.</font><br>"
        else:
            msg += "<font color='#f44336'>[FAIL] WARNING: Extension mismatch! Possible spoofing.</font><br>"
            
        if "error" in vt:
            msg += f"<font color='orange'>VirusTotal: {vt['error']}</font>"
        elif vt.get("status") == "unknown":
            msg += "<font color='orange'>VirusTotal: File never seen before.</font>"
        else:
            malicious = vt.get('malicious', 0)
            target_color = '#f44336' if malicious > 0 else '#4caf50'
            msg += f"<font color='{target_color}'>VirusTotal: Flagged by {malicious} engines.</font>"
            
        self.status_label.setText(msg)
        
    def export_report(self):
        if not self.last_scan_result: return
        
        try:
            r = self.last_scan_result
            path = generate_pdf_report(r['file_path'], r['extension'], r['detected'], r['vt'])
            QMessageBox.information(self, "Saved", f"Report saved successfully to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save report: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec())
