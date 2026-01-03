import sys
import os

import thrember
import lightgbm as lgb

os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

DEFAULT_DIR = "malwares/default"

WIN32_PATH = "src/EMBER2024_Win32.model"
PE_PATH = "src/EMBER2024_PE.model"
GENERAL_PATH = "src/EMBER2024_all.model"

def load_models(model_choice):
    models = {}
    if model_choice in ("win32", "all"):
        models["win32"] = lgb.Booster(model_file=WIN32_PATH)
    if model_choice in ("pe", "all"):
        models["pe"] = lgb.Booster(model_file=PE_PATH)
    if model_choice in ("general", "all"):
        models["general"] = lgb.Booster(model_file=GENERAL_PATH)
    return models

def list_targets(directory, sha256=None):
    if sha256:
        return [os.path.join(directory, f"{sha256}.exe")]
    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(".exe") and os.path.isfile(os.path.join(directory, f))
    ]

def predict_file(filepath, models):
    results = {}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        for k, model in models.items():
            try:
                results[k] = float(thrember.predict_sample(model, data))
            except Exception:
                results[k] = None
    except Exception:
        for k in models:
            results[k] = None
    return results

if len(sys.argv) < 3:
    print("Usage: python3 predict-interface.py <directory|DEFAULT> <model> [hash]")
    sys.exit(1)

directory_arg = sys.argv[1]
model_choice = sys.argv[2].lower()
sha256 = sys.argv[3] if len(sys.argv) >= 4 else None

if model_choice not in ("win32", "pe", "general", "all"):
    print("Model must be one of: win32 | pe | general | all")
    sys.exit(1)

malware_dir = DEFAULT_DIR if directory_arg == "DEFAULT" else directory_arg

if not os.path.isdir(malware_dir):
    print("Invalid directory:", malware_dir)
    sys.exit(1)

models = load_models(model_choice)
targets = list_targets(malware_dir, sha256)

if not targets:
    print("No matching files found.")
    sys.exit(0)

def print_results(filepath, results):
    sha = os.path.basename(filepath)
    out = [sha]
    for k, v in results.items():
        if v is not None:
            out.append(f"{k}={v:.6f}")
    print(" | ".join(out))

stats = {}
for k in models:
    stats[k] = {"total": 0, "above": 0}

for filepath in targets:
    results = predict_file(filepath, models)
    print_results(filepath, results)
    for k, v in results.items():
        if v is not None:
            stats[k]["total"] += 1
            if v > 0.5:
                stats[k]["above"] += 1

print("==== Statistics ====")
for k in stats:
    print(f"{k}: {stats[k]['above']} / {stats[k]['total']} detected as malware.")
