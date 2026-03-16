from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os
import datetime

def generate_pdf_report(file_path, file_extension, detected_type, vt_results, output_path=None):
    """Generates a professional PDF report containing the scan results."""
    
    if output_path is None:
        filename = os.path.basename(file_path)
        output_path = os.path.join(os.path.dirname(file_path), f"{filename}_scan_report.pdf")
        
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    
    # Header
    c.setFont("Helvetica-Bold", 24)
    c.drawString(100, height - 80, "File Type & Malware Scan Report")
    
    c.setFont("Helvetica", 12)
    c.drawString(100, height - 110, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.line(100, height - 120, width - 100, height - 120)
    
    # File Details
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, height - 150, "File Information")
    
    c.setFont("Helvetica", 12)
    c.drawString(120, height - 175, f"File Path: {file_path}")
    c.drawString(120, height - 195, f"Claimed Extension: {file_extension.upper()}")
    c.drawString(120, height - 215, f"Detected Magic Number: {detected_type.upper()}")
    
    y_pos = height - 245
    
    # Integrity Check
    if file_extension.lower() == detected_type.lower() or detected_type == "Unknown":
        c.setFillColor(colors.green)
        c.drawString(120, y_pos, "[PASS] Extension matches detected file type.")
    else:
        c.setFillColor(colors.red)
        c.drawString(120, y_pos, "[FAIL] WARNING: Extension mismatch. This file may be masquerading.")
        
    c.setFillColor(colors.black)
    c.line(100, y_pos - 15, width - 100, y_pos - 15)
    
    # VirusTotal Results
    y_pos -= 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, y_pos, "VirusTotal Analysis")
    
    c.setFont("Helvetica", 12)
    if "error" in vt_results:
        c.setFillColor(colors.red)
        c.drawString(120, y_pos - 25, f"Error: {vt_results['error']}")
    elif vt_results.get("status") == "unknown":
        c.setFillColor(colors.orange)
        c.drawString(120, y_pos - 25, "File hash not found in VirusTotal database.")
        c.drawString(120, y_pos - 45, f"SHA-256: {vt_results['hash']}")
    else:
        c.setFillColor(colors.black)
        c.drawString(120, y_pos - 25, f"SHA-256: {vt_results['hash']}")
        
        malicious = vt_results.get("malicious", 0)
        total = vt_results.get("total_engines", 0)
        
        y_pos -= 50
        if malicious > 0:
            c.setFillColor(colors.red)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(120, y_pos, f"MALICIOUS: Flagged by {malicious} / {total} engines.")
        else:
            c.setFillColor(colors.green)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(120, y_pos, f"CLEAN: Flagged by 0 / {total} engines.")

    c.save()
    return output_path
