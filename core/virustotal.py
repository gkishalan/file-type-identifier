import hashlib
import requests
import json
import os

API_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "vt_config.json")

def get_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            data = json.load(f)
            return data.get("api_key")
    return None

def save_api_key(key):
    with open(API_KEY_FILE, "w") as f:
        json.dump({"api_key": key}, f)

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_file_with_vt(file_path, gui_callback=None):
    """
    Calculates the hash of the file and queries VirusTotal.
    gui_callback is an optional function that takes a percentage (0-100) or a status string.
    """
    api_key = get_api_key()
    if not api_key:
        return {"error": "No API Key configured. Please add one in settings."}
        
    if gui_callback:
        gui_callback("Computing SHA-256 hash...")
        
    file_hash = calculate_sha256(file_path)
    
    if gui_callback:
        gui_callback("Querying VirusTotal...")
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + undetected
            
            return {
                "hash": file_hash,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "status": "clean" if malicious == 0 else "malicious"
            }
        elif response.status_code == 404:
            return {
                "hash": file_hash,
                "status": "unknown",
                "message": "File hash not found in VirusTotal database (never scanned before)."
            }
        elif response.status_code == 401:
            return {"error": "Invalid API Key."}
        else:
            return {"error": f"API Error HTTP {response.status_code}: {response.text}"}
            
    except Exception as e:
        return {"error": str(e)}
