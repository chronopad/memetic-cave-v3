import sys
import os

import ember
import lightgbm as lgb
from src.malconv_nn import malconv

os.environ["CUDA_VISIBLE_DEVICES"] = ""
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

DEFAULT_DIR = "malwares/default"
MALCONV_PATH = "src/MalConv.model"
EMBER_PATH = "src/EMBER2018.model"

def load_models(model_choice):
    models = {}
    if model_choice in ("malconv", "both"): models["malconv"] = malconv(MALCONV_PATH)
    if model_choice in ("ember", "both"): models["ember"] = lgb.Booster(model_file=EMBER_PATH)
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
    if "malconv" in models:
        try:
            results["malconv"] = float(models["malconv"].predict(filepath))
        except Exception:
            results["malconv"] = None
    if "ember" in models:
        try:
            with open(filepath, "rb") as f:
                results["ember"] = float(ember.predict_sample(models["ember"], f.read()))
        except Exception:
            results["ember"] = None
    return results

if len(sys.argv) < 3:
    print("Usage: python3 predict-interface.py <directory|DEFAULT> <model> [hash]")
    sys.exit(1)

directory_arg = sys.argv[1]
model_choice = sys.argv[2].lower()
sha256 = sys.argv[3] if len(sys.argv) >= 4 else None

if model_choice not in ("malconv", "ember", "both"):
    print("Model must be one of: malconv | ember | both")
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
    if "malconv" in results and results["malconv"] is not None:
        out.append(f"malconv={results['malconv']:.6f}")
    if "ember" in results and results["ember"] is not None:
        out.append(f"ember={results['ember']:.6f}")
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

# python3 predict-interface.py DEFAULT malconv
# python3 predict-interface.py samples ember
# python3 predict-interface.py samples both d41d8cd98f
