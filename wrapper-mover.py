import os 
import sys

if len(sys.argv) <= 2:
    print("python3 wrapper-mover.py <filePath> <targetDir>")
    sys.exit(1)

filePath = sys.argv[1]
targetDir = sys.argv[2]

if not targetDir.startswith("malwares/"):
    targetDir = f"malwares/{targetDir}"

if os.path.isdir(targetDir):
    os.system(f"rm -rf {targetDir}")
os.mkdir(targetDir)
os.system(f"cp {filePath} {targetDir}")