import os 
import sys
import subprocess
import re

if len(sys.argv) <= 3:
    print("python3 pipeline-1.py <testId> <sourceDir> <fileHash> <optimizer> [--verbose]")
    sys.exit(1)

testId    = sys.argv[1]
sourceDir = sys.argv[2]
fileHash  = sys.argv[3]
optimizer = sys.argv[4]
VERBOSE   = "--verbose" in sys.argv

ENVIRONMENT_1 = "memetic-cave"
ENVIRONMENT_2 = "memetic-cave-v3"
LOAD_PYENV = (
    'export PYENV_ROOT="$HOME/.pyenv"; '
    'export PATH="$PYENV_ROOT/bin:$PATH"; '
    'eval "$(pyenv init --path)"; '
    'eval "$(pyenv init -)"; '
    'eval "$(pyenv virtualenv-init -)"'
)

def run_cmd(cmd):
    p = subprocess.run(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if VERBOSE:
        if p.stdout:
            print(p.stdout, end="")
        if p.stderr:
            print(p.stderr, end="", file=sys.stderr)
    return p.stdout

def getMalConvScore(sourceDir, fileHash):
    cmd = (
        f'{LOAD_PYENV}; '
        f'pyenv activate {ENVIRONMENT_1}; '
        f'python3 predict-interface-v1.py {sourceDir} malconv {fileHash}; '
        f'pyenv deactivate'
    )

    out = run_cmd(cmd)
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

    out = run_cmd(cmd)
    m = re.search(r"pe=([0-9.]+)", out)
    if not m:
        raise RuntimeError("EMBER PE score not found in output :(")
    return float(m.group(1))

def geneticOptimizationYuste(targetDir):
    cmd = (
        f'{LOAD_PYENV}; '
        f'pyenv activate {ENVIRONMENT_1}; '
        f'python3 genetic_optimization_v1.py --path {targetDir}; '
        f'pyenv deactivate'
    )

    run_cmd(cmd)

def memeticOptimization(filepath):
    cmd = (
        f'{LOAD_PYENV}; '
        f'pyenv activate {ENVIRONMENT_1}; '
        f'python3 memetic_optimization_v2.py {filepath}; '
        f'pyenv deactivate'
    )

    run_cmd(cmd)

outdir = f"malwares/expgen-b{testId}"
if os.path.isdir(outdir):
    os.system(f"rm -rf {outdir}")
os.mkdir(outdir)
os.system(f"cp {sourceDir}/{fileHash}.exe {outdir}")

initMalConvScore = getMalConvScore(sourceDir, fileHash)
initEMBER2024PEScore = getEMBER2024PEScore(sourceDir, fileHash)

print("Starting modification...")
if optimizer == "genetic": geneticOptimizationYuste(outdir)
elif optimizer == "memetic": memeticOptimization(f"{outdir}/{fileHash}.exe")
print("Finished modification!")

finalMalConvScore = getMalConvScore(outdir, fileHash)
finalEMBER2024PEScore = getEMBER2024PEScore(outdir, fileHash)

print("=" * 60)
print(f"Test ID        : {testId}")
print(f"Sample         : {fileHash}.exe")
print(f"Source Dir     : {os.path.abspath(sourceDir)}")
print(f"Optimized Dir  : {os.path.abspath(outdir)}")
print("-" * 60)
print("Initial scores")
print(f"  MalConv      : {1 if initMalConvScore > 0.5 else 0} ({initMalConvScore:.6f})")
print(f"  EMBER2024 PE : {1 if initEMBER2024PEScore > 0.5 else 0} ({initEMBER2024PEScore:.6f})")
print("-" * 60)
print("Final scores")
print(f"  MalConv      : {1 if finalMalConvScore > 0.5 else 0} ({finalMalConvScore:.6f})")
print(f"  EMBER2024 PE : {1 if finalEMBER2024PEScore > 0.5 else 0} ({finalEMBER2024PEScore:.6f})")
print("-" * 60)
print("Delta")
print(f"  MalConv      : {finalMalConvScore - initMalConvScore:+.6f}")
print(f"  EMBER2024 PE : {finalEMBER2024PEScore - initEMBER2024PEScore:+.6f}")
print("=" * 60)