import os
import subprocess
import argparse

def runCommand(cmd):
    p = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout

def getScores(filePath):
    malconvScore = float(runCommand(f"python3 wrapper-score.py {filePath} MalConv"))
    ember2024peScore = float(runCommand(f"python3 wrapper-score.py {filePath} EMBER2024_PE"))

    return f"malconv=[{1 if malconvScore > 0.5 else 0} ({malconvScore})] ember=[{1 if ember2024peScore > 0.5 else 0} ({ember2024peScore})]"

parser = argparse.ArgumentParser(description="Main pipeline orchestrator utility")
parser.add_argument("file_path", help="Path to malware file")
parser.add_argument("target_dir", nargs="?", default=None, help="New directory to work in")
args = parser.parse_args()

workDir = ""
fileName = os.path.splitext(os.path.basename(args.file_path))[0]
if args.target_dir is None:
    workDir = os.path.dirname(args.file_path)
    print(f"Working directly in directory: {workDir}")
else:
    if not args.target_dir.startswith("malwares/"):
        args.target_dir = "malwares/" + args.target_dir

    workDir = os.path.abspath(args.target_dir)
    print(f"[*] Creating new work directory: {workDir}")
    runCommand(f"python3 wrapper-mover.py {args.file_path} {args.target_dir}")
filePath = f"{workDir}/{fileName}"

print(f"[!] Initial score: {getScores(filePath)}")