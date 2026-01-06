import os
import argparse
import logging
import shutil
import random

import pefile
from src.malconv_nn import malconv

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description="Pipeline 2: Dataset preprocessing pipeline (env: memetic-cave)")
parser.add_argument("dataset_path", help="Path to malware directory (dataset)")
parser.add_argument("filtered_path", help="Path to output directory (filtered malwares)")
parser.add_argument("--amount", default=999999, help="Maximum amount of files to use")
args = parser.parse_args()
model = malconv("src/MalConv.model")

dataset_path = os.path.abspath(args.dataset_path)
filtered_path = os.path.abspath(args.filtered_path)
max_counter = int(args.amount)

class ExceededMaxSize(Exception):
    pass 

class NotDetected(Exception):
    pass

class NotPE(Exception):
    pass 

def checkFileSize(filepath):
    filesize = os.path.getsize(filepath)
    if filesize > 1000000: raise ExceededMaxSize  # Error if exceeded 1MB

def checkInitScore(filepath):
    pred = model.predict(filepath)
    if pred < 0.5: raise NotDetected              # Error if not detected

def checkIsFilePE(filepath):
    file = pefile.PE(filepath, fast_load=True)
    if not file.is_exe(): raise NotPE             # Error if not PE (EXE)

if not os.path.isdir(filtered_path):
    logging.info("[*] Creating output directory.") 
    os.mkdir(filtered_path)                        # Create output directory if doesn't exist
else:
    logging.info("[*] Output directory exists.")

valid_counter = 0
files = os.listdir(dataset_path)
while valid_counter < max_counter and files:
    f = random.choice(files)
    files.remove(f)
    try:
        filepath = os.path.join(dataset_path, f)
        checkFileSize(filepath)  # Check initial file size (<= 1 MB)
        checkInitScore(filepath) # Check MalConv (or other model) initial prediction
        checkIsFilePE(filepath)  # Check if file is a valid PE

        logging.info(f"[*] Valid file: {f}")
        shutil.copy(filepath, filtered_path)
        valid_counter += 1
    except ExceededMaxSize:
        logging.error(f"[!] ExceededMaxSize error: {f}")
    except NotDetected:
        logging.error(f"[!] NotDetected error: {f}")
    except NotPE:
        logging.error(f"[!] NotPE error: {f}")
logging.info(f"[*] Total valid files: {valid_counter}")
logging.info(f"[*] Files can be found in {filtered_path}")
