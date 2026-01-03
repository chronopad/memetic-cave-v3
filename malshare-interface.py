import requests
from tqdm import trange

r = requests.get("https://malshare.com/api.php?api_key=8e12cf3a49d442ac59caa550326783f06363ed487f754b09266de56e9fbc9e23&action=type&type=pe32")
rawHashes = r.json()

hashes = [rawHash["sha256"] for rawHash in rawHashes]
for i in trange(len(hashes)):
    URL = f"https://malshare.com/api.php?api_key=8e12cf3a49d442ac59caa550326783f06363ed487f754b09266de56e9fbc9e23&action=getfile&hash={hashes[i]}"
    print("Downloading from : " +  URL)
    r = requests.get(URL)
    
    with open("malwares/malshare-v1/" + hashes[i] + ".exe", "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)