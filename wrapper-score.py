import os 
import sys
import subprocess
import re

if len(sys.argv) <= 2:
    print("python3 wrapper-score.py <filePath> <modelName>")
    sys.exit(1)

filePath = sys.argv[1]
modelName = sys.argv[2]

ENVIRONMENT_1 = "memetic-cave"
ENVIRONMENT_2 = "memetic-cave-v3"
LOAD_PYENV = (
    'export PYENV_ROOT="$HOME/.pyenv"; '
    'export PATH="$PYENV_ROOT/bin:$PATH"; '
    'eval "$(pyenv init --path)"; '
    'eval "$(pyenv init -)"; '
    'eval "$(pyenv virtualenv-init -)"'
)
VALID_MODELS = ["EMBER2024_PE", "MalConv"]

def runCommand(cmd):
    p = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout
        
def getMalConvScore(sourceDir, fileHash):
    cmd = (
        f'{LOAD_PYENV}; '
        f'pyenv activate {ENVIRONMENT_1}; '
        f'python3 predict-interface-v1.py {sourceDir} malconv {fileHash}; '
        f'pyenv deactivate'
    )

    out = runCommand(cmd)
    m = re.search(r"malconv=([0-9.]+)", out)
    if not m:
        raise RuntimeError("MalConv score not found in output :(")
    return float(m.group(1))

def getEMBER2024PEScore(sourceDir, fileHash):
    cmd = (
        f'{LOAD_PYENV}; '
        f'pyenv activate {ENVIRONMENT_2}; '
        f'python3 predict-interface-v2.py {sourceDir} pe {fileHash}; '
        f'pyenv deactivate'
    )

    out = runCommand(cmd)
    m = re.search(r"pe=([0-9.]+)", out)
    if not m:
        raise RuntimeError("EMBER PE score not found in output :(")
    return float(m.group(1))

def getScore(filePath, modelName):
    sourceDir = os.path.dirname(filePath)
    fileName = os.path.splitext(os.path.basename(filePath))[0]

    if modelName == "EMBER2024_PE":
        return getEMBER2024PEScore(sourceDir, fileName)
    elif modelName == "MalConv":
        return getMalConvScore(sourceDir, fileName)

if modelName not in VALID_MODELS:
    print("Please provide a valid model:", VALID_MODELS)
    sys.exit(1)

print(getScore(filePath, modelName))