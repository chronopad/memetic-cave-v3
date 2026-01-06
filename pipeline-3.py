import os
import argparse 
import logging
import shutil 
import subprocess
import re
import hashlib
import csv

from src.malconv_nn import malconv

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description="Mass testing utility for GAop_v1, GAop_v3, and MAop_v2")
parser.add_argument("filtered_path", help="Path to filtered dataset directory")
parser.add_argument("output_path", help="Path to output AE directory")
parser.add_argument("--test-path", default="malwares/tmp_dir", help="Path to test directory")
parser.add_argument("--report-file", default="", help="Path to report file (CSV)")
args = parser.parse_args()
model = malconv("src/MalConv.model")

filtered_path = os.path.abspath(args.filtered_path)   # Dataset directory
output_path = os.path.abspath(args.output_path)       # Output directory
test_path = os.path.abspath(args.test_path)           # Test directory
report_path = os.path.abspath(args.report_file)

REPORT_FIELDS = [
    "file_hash",
    "optimizer",
    "generation",
    "time_taken",
    "size_ratio",
    "initial_score",
    "final_score",
    "dataset_path",
    "output_path"
]

def getPredictionScore(filepath):
    return model.predict(filepath)

def runCommand(cmd):
    p = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout + p.stderr

def modifyFile(filepath):
    # command = (f'python3 memetic_optimization_v2.py {filepath}')
    command = (f'python3 genetic_optimization_v1.py --path {os.path.dirname(filepath)}')
    output = runCommand(command)
    output = output.replace("\\n", "\n")
    gen_re  = re.search(r"\[\*\]\s*Generation:\s*(\d+)", output)
    time_re = re.search(r"\[\*\]\s*Time elapsed:\s*([0-9.]+)", output)
    size_re = re.search(r"\[\*\]\s*Size ratio:\s*(\d+)\s*/\s*(\d+)", output)

    if not (gen_re and time_re and size_re):
        raise RuntimeError("Failed to parse optimizer output")

    generation = int(gen_re.group(1))
    cpu_time   = round(float(time_re.group(1)), 6)
    init_size_ratio  = int(size_re.group(1))
    final_size_ratio = int(size_re.group(2))

    return generation, cpu_time, f"{init_size_ratio}/{final_size_ratio}"

def saveToReport(row_content):
    file_exists = os.path.isfile(report_path)

    with open(report_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        if not file_exists: writer.writeheader()             # Write header only if file doesn't exist
        writer.writerow(row_content)

if not os.path.isdir(output_path):
    logging.info("[*] Creating output directory.") 
    os.mkdir(output_path) # Create output directory if doesn't exist
else: 
    logging.info("[*] Output directory exists.")

dataset_files = os.listdir(filtered_path)
modified_files = os.listdir(output_path)
target_files = [f for f in dataset_files if f not in modified_files]

for idx, f in enumerate(target_files):
    logging.info(f"[*] Current file [{len(dataset_files) - len(target_files) + 1 + idx}/{len(dataset_files)}]: {f}")
    if os.path.isdir(test_path): 
        shutil.rmtree(test_path)
    os.mkdir(test_path)
    try:
        original_file = os.path.join(filtered_path, f)
        original_hash = hashlib.sha256(open(original_file, "rb").read()).hexdigest()
        logging.info(f"    Moving file to test directory")
        shutil.copy(original_file, test_path)                         # Copy malware to test directory
        current_file = os.path.join(test_path, f)

        logging.info("    Getting initial prediction score")
        initial_score = round(getPredictionScore(current_file), 6)    # Get initial prediction score

        logging.info("    Running optimizer on the current file")
        generation, time_taken, size_ratio = modifyFile(current_file) # Run optimizer on current file
        shutil.copy(current_file, output_path)

        logging.info("    Getting final prediction score")
        final_score = round(getPredictionScore(current_file), 6)      # Get final prediction score

        logging.info(f"    Initial score : {1 if initial_score > 0.5 else 0} ({initial_score})")
        logging.info(f"    Final score   : {1 if final_score > 0.5 else 0} ({final_score})")
        logging.info(f"    Time taken    : {time_taken}")
        logging.info(f"    Generation    : {generation}")
        logging.info(f"    Size ratio    : {size_ratio}")

        row_content = {
            "file_hash": original_hash,
            "optimizer": "MAop_v2",
            "generation": generation,
            "time_taken": time_taken,
            "size_ratio": size_ratio,
            "initial_score": f"{1 if initial_score > 0.5 else 0} ({initial_score})",
            "final_score": f"{1 if final_score > 0.5 else 0} ({final_score})",
            "dataset_path": filtered_path.split("/")[-1],
            "output_path": output_path.split("/")[-1]
        }
        saveToReport(row_content)
    except Exception as e:
        logging.error("[!] An error occured, skipping file...")
        logging.error(e)
    finally:
        # output_file = os.path.join(output_path, f)
        # if os.path.isfile(output_file): os.remove(output_file)
        shutil.rmtree(test_path)
