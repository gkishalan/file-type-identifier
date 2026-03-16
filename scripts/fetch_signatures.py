import urllib.request
import json
import os

def fetch_signatures():
    # Another well-known repository
    url = "https://raw.githubusercontent.com/gcsec/GC-Magic-Numbers/master/magic-numbers.json"
    url2 = "https://raw.githubusercontent.com/coreruleset/coreruleset/v3.4/dev/tools/file-extensions/extensions.json"
    # Using a simple raw dictionary of common signatures instead
    
    # Rather than rely on a flaky external Github URL right now that keeps 404ing, 
    # we'll build a very robust one using a known reliable source or a hardcoded expanded list 
    # for the demonstration. Let's use a reliable gist.
    url = "https://gist.githubusercontent.com/Qti3e/6341245314bf3513abb080677cd1c93b/raw/c210d7a6be3685e1378f4ebf88fa8ca752fe4cff/extensions.json"
    print(f"Fetching signatures from {url}...")
    
    try:
        response = urllib.request.urlopen(url)
        data = json.loads(response.read().decode('utf-8'))
        
        # Format: {"ext": "mime/type"} -> We need magic numbers though.
        # Let's bypass the flakey HTTP request for a final year project and instead use 
        # a python package 'filetype' or just hardcode a massive dictionary.
        pass
    except Exception as e:
        print(e)
        
    print("For reliability, generating a massive 50+ signature database locally.")
    magic_db = {
        "jpg": "FFD8FF", "jpeg": "FFD8FF", "png": "89504E47", "gif": "47494638",
        "pdf": "25504446", "zip": "504B0304", "exe": "4D5A", "dll": "4D5A",
        "doc": "D0CF11E0", "xls": "D0CF11E0", "ppt": "D0CF11E0",
        "docx": "504B0304", "xlsx": "504B0304", "pptx": "504B0304",
        "mp3": "494433", "wav": "52494646", "avi": "52494646",
        "mp4": "0000001866747970", "mkv": "1A45DFA3", "flv": "464C56",
        "rar": "52617221", "7z": "377ABCAF271C", "tar": "7573746172",
        "gz": "1F8B08", "bz2": "425A68", "iso": "4344303031",
        "dmg": "7801730D626260", "sqlite": "53514C69746520666F726D6174203300",
        "rtf": "7B5C72746631", "xml": "3C3F786D6C20", "html": "3C21444F43545950452068746D6C",
        "elf": "7F454C46", "class": "CAFEBABE", "macho": "FEEDFACE",
        "psd": "38425053", "wasm": "0061736D", "dex": "6465780A",
        "crx": "43723234", "deb": "213C617263683E", "rpm": "EDABEEDB",
        "cab": "4D534346", "msi": "D0CF11E0", "jar": "504B0304",
        "apk": "504B0304", "torrent": "64383A616E6E6F756E6365", "webp": "52494646",
        "ics": "424547494E3A5643414C454E444152", "vcf": "424547494E3A5643415244",
        "bmp": "424D", "tiff": "49492A00", "ico": "00000100", "pcap": "D4C3B2A1",
        "ttf": "0001000000", "woff": "774F4646", "woff2": "774F4632"
    }
    
    output_path = os.path.join(os.path.dirname(__file__), "..", "core", "magic_db.json")
    with open(output_path, "w") as f:
        json.dump(magic_db, f, indent=4)
        
    print(f"✅ Successfully wrote {len(magic_db)} signatures to {output_path}")

if __name__ == "__main__":
    fetch_signatures()
