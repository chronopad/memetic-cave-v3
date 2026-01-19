import time
import random
import logging
import argparse
import signal
import shutil
import os

from deap import base, creator, tools
from src.malconv_nn import malconv
import mmap

import pefile
import r2pipe

parser = argparse.ArgumentParser(description="MAop_v1 optimizer algorithm script")
parser.add_argument("file_path", help="Path to malware file")
args = parser.parse_args()
logging.basicConfig(level=logging.INFO)

model = malconv("src/MalConv.model")
INIT_SIZE_RATIO = 10

class NotPE(Exception):
    pass

class InvalidArgs(Exception):
    pass

class InvalidExpandingSectionsReq(Exception):
    pass

class r2_bind():
    def __init__(self, binary):
        self.closed = True
        self.open_r2_pe(binary)

    def get_number_of_sections(self):
        return self.r2.cmdj("iSj")

    def run_cmdj(self, cmd):
        if not self.closed:
            return self.r2.cmdj(cmd)
        else:
            return None

    def is_closed(self):
        return self.closed

    def close(self):
        try:
            self.r2.quit()
        except:
            pass
        try:
            self.r2n.quit()
        except:
            pass
        try:
            self.pe.close()
        except:
            pass
        self.closed = True

    def size_of_file(self):
        return self.r2n.cmd("r")

    def open_r2_pe(self, binary):
        try:
            self.binary = binary
            self.pe = pefile.PE(binary, fast_load=True)
            if not self.pe.is_exe():
                self.pe.close()
                raise NotPE()
            elif self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 or \
                    self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size != 0:
                self.pe.close()
                raise NotPE()
            self.r2n = r2pipe.open(binary, ['-2', '-n'])
            logging.info("Binary size: " + str(int(self.r2n.cmd("r"))))
            self.r2 = r2pipe.open(binary, ['-2'])
            self.closed = False
        except NotPE:
            raise
        except Exception:
            raise

    def reopen_r2_pe(self, binary=None):
        if binary == None:
            binary = self.binary
        self.close()
        self.open_r2_pe(binary)

    def overwrite_file(self, binary):
        shutil.copy(binary, self.binary)

    def get_dict_spaces_prioritize_n(self, size, n, prioritize):
        if size > 100 or size < 0:
            raise Exception
        bin_size = int(self.r2.cmd('r'))
        desired_size = int(bin_size * (size * 0.01))
        pieces = int(desired_size / self.pe.OPTIONAL_HEADER.FileAlignment)

        dict_spaces = {}
        sections_info = self.r2.cmdj('iSj')
        for counter, section in enumerate(sections_info):
            dict_spaces[counter] = 0

        count = 0
        while pieces > 0:
            if sections_info[n]['size'] > 0 and sections_info[n]['paddr'] > 0 and \
                    random.randint(0, 100) < prioritize:
                dict_spaces[n] += self.pe.OPTIONAL_HEADER.FileAlignment
            else:
                section = count % len(sections_info)
                if section == n:
                    section += 1
                    count += 1
                if sections_info[section]['size'] > 0 and sections_info[section]['paddr'] > 0:
                    dict_spaces[section] += self.pe.OPTIONAL_HEADER.FileAlignment
                    pieces -= 1
                count += 1

        return dict_spaces

    def get_dict_spaces(self, size, section_expand=0):
        if size > 100 or size < 0:
            raise Exception
        bin_size = int(self.r2.cmd('r'))
        desired_size = int(bin_size * (size * 0.01))
        pieces = max(int(desired_size / self.pe.OPTIONAL_HEADER.FileAlignment), 1)

        dict_spaces = {}
        sections_info = self.r2.cmdj('iSj')
        for counter, section in enumerate(sections_info):
            dict_spaces[counter] = 0

        if section_expand == -1:
            count = 0
            while pieces > 0:
                section = count % len(sections_info)
                if sections_info[section]['size'] > 0 and sections_info[section]['paddr'] > 0:
                    dict_spaces[section] += self.pe.OPTIONAL_HEADER.FileAlignment
                    pieces -= 1
                count += 1
        elif sections_info[section_expand]['size'] > 0 and sections_info[section_expand]['paddr'] > 0:
            while pieces > 0:
                dict_spaces[section_expand] += self.pe.OPTIONAL_HEADER.FileAlignment
                pieces -= 1
        else:
            dict_spaces[0] = 9999999999999999

        return dict_spaces

    def round_up_file_alignment(self, size):
        logging.debug("Requested rounding up to file alignment of %s", str(size))
        if (size % self.pe.OPTIONAL_HEADER.FileAlignment):
            size = (int(size / self.pe.OPTIONAL_HEADER.FileAlignment) + (
                    size % self.pe.OPTIONAL_HEADER.FileAlignment > 0)) * self.pe.OPTIONAL_HEADER.FileAlignment
            logging.debug("Rounded up to %s", str(size))
        else:
            logging.debug("Did not have to round")
        return size

    def round_up_virtual_alignment(self, size):
        logging.debug("Requested rounding up to section alignment of %s", str(size))
        if (size % self.pe.OPTIONAL_HEADER.SectionAlignment):
            size = (int(size / self.pe.OPTIONAL_HEADER.SectionAlignment) + (
                    size % self.pe.OPTIONAL_HEADER.SectionAlignment > 0)) * self.pe.OPTIONAL_HEADER.SectionAlignment
            logging.debug("Rounded up to %s", str(size))
        else:
            logging.debug("Did not have to round")
        return size

    def expand_sections_inserting(self, spaces, section_data_):
        try:
            sections_info = self.r2.cmdj('iSj')
            total_additional_size = sum(spaces.values())
            
            # 1. Close all handles before modifying the file on disk
            self.close() 

            # 2. Expand the file size at the OS level (Efficient)
            current_size = os.path.getsize(self.binary)
            with open(self.binary, "ab") as f:
                f.truncate(current_size + total_additional_size)

            # 3. Use one R2 session to shift data if necessary, or 
            # just proceed to fix headers if you are only adding padding
            logging.debug("Fixing headers with pefile")
            result = self.fix_headers(self.binary, spaces, sections_info, section_data_)
            
            return result
        except Exception as e:
            logging.error(f"Expansion failed: {e}")
            raise

    def fix_headers(self, binary, spaces, sections_info, section_data_):
        try:
            pe = pefile.PE(binary, fast_load=True)
            size_to_add = 0
            result = {}
            for counter, section in enumerate(pe.sections):
                size_to_add += spaces[counter]

                if pe.sections[counter].PointerToRawData > 0 and pe.sections[counter].SizeOfRawData > 0:
                    pe.sections[counter].PointerToRawData += size_to_add
                    section_data_['sections'][sections_info[counter]['name']]['start_p_address'] += size_to_add

                section_info = {}
                section_info['size'] = spaces[counter]
                section_info['start_p_address'] = pe.sections[counter].PointerToRawData - spaces[counter]
                result[counter] = section_info

            pe.write(f"{binary}.tmp")
            pe.close()
            shutil.copy(f"{binary}.tmp", binary)
            os.remove(f"{binary}.tmp")

            return result
        except Exception as e:
            logging.exception(e)
            if 'pe' in locals():
                pe.close()
            raise Exception

    def get_expand_sections(self, data, size, section_expand=0):
        spaces = self.get_dict_spaces(size, section_expand)
        logging.info("[+] Checkpoint 1.2.1")
        if spaces[0] == 9999999999999999:
            return None
        else:
            logging.info("[+] Checkpoint 1.2.2")
            return self.expand_sections_inserting(spaces, data)

    def expand_single_section(self, spaces):
        try:
            sections_info = self.r2.cmdj('iSj')
            for i in range(0, len(sections_info)):
                if (spaces[i] % self.pe.OPTIONAL_HEADER.FileAlignment):
                    logging.info(
                        "[!] WARNING: expanding space requested ({}) is not file aligned, rounding it up".format(
                            str(spaces[i])))
                    spaces[i] = (int(spaces[i] / self.pe.OPTIONAL_HEADER.FileAlignment) + (spaces[
                                                                                               i] % self.pe.OPTIONAL_HEADER.FileAlignment > 0)) * self.pe.OPTIONAL_HEADER.FileAlignment
                    logging.info("[!] New Value: {}".format(str(spaces[i])))

            f = open(self.binary, "r+b")
            mm = mmap.mmap(f.fileno(), 0, mmap.ACCESS_WRITE)

            fout = open(self.binary + ".copy", "w+b")

            for counter, section in enumerate(sections_info):
                if sections_info[counter]['size'] > 0 and sections_info[counter]['paddr'] > 0:
                    initial_address = sections_info[counter]['paddr']
                    data = mm.read(initial_address)
                    fout.write(data)
                    break

            chunksize = 2048

            pieces = int(spaces[counter] / chunksize)
            for _ in range(pieces):
                fout.write(b'\x00' * chunksize)

            last_piece = int(spaces[counter] % chunksize)
            if last_piece > 0:
                fout.write(b'\x00' * last_piece)

            while mm.size() > (mm.tell() + chunksize):
                data = mm.read(chunksize)
                fout.write(data)

            f.close()
            fout.close()
            mm.close()
            self.overwrite_file(self.binary + ".copy")
            self.reopen_r2_pe()
            return initial_address

        except InvalidExpandingSectionsReq:
            raise
        except Exception as e:
            print(e)
            if 'f' in locals():
                if not f.closed:
                    f.close()
            if 'fout' in locals():
                if not fout.closed:
                    fout.close()
            if 'mm' in locals():
                if not mm.closed:
                    mm.close()

    def main(self, size, section_expand=0):
        data = {}
        logging.info("[+] Checkpoint 1.1")
        data['sections'] = self.get_sections_spaces_aggressive()
        logging.info("[+] Checkpoint 1.2")
        data['expand'] = self.get_expand_sections(data=data, size=size, section_expand=section_expand)
        logging.info("[+] Checkpoint 1.3")
        return data

    def get_sections_spaces_aggressive(self):
        return self.get_sections_ph_padding()

    def get_sections_ph_padding(self):
        result = {}
        sections_info = self.r2.cmdj('iSj')
        for counter, section in enumerate(sections_info):
            section_dict = {}
            name = section['name']

            if sections_info[counter]['size'] > 0 and sections_info[counter]['paddr'] > 0:
                size = self.get_pattern_backwards_big_chunk_ph(section['paddr'] + section['size'], section['paddr'], 0)
                size -= 16
                start_p_address = section['paddr'] + section['size'] - size

                section_dict['start_p_address'] = start_p_address
                section_dict['size'] = size
                result[name] = section_dict

            else:
                section_dict['start_p_address'] = 0
                section_dict['size'] = 0
                result[name] = section_dict
        return result

    def get_pattern_backwards_big_chunk_ph(self, start_addr, end_addr, pattern):
        size = 4096
        result = 0
        while size > 1:
            pattern_size = self.get_pattern_backwards_ph(start_addr, end_addr, pattern, size)
            start_addr -= pattern_size
            result += pattern_size
            size = int(size / 2)
        return result

    def get_pattern_backwards_ph(self, start_addr, end_addr, pattern, size=4):
        result = 0
        stop = False
        start_addr -= size
        while not stop and start_addr >= end_addr:
            hex_bytes = self.r2n.cmdj('pxj ' + str(size) + ' @' + str(start_addr))
            for byte in hex_bytes:
                if byte != pattern:
                    stop = True
                    break
            if not stop:
                result += size
                start_addr -= size
        return result

class Timeout():
    class TimeoutError(Exception):
        pass

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)

    def raise_timeout(self, *args):
        raise Timeout.TimeoutError()

class MemeticOptimizer():
    def __init__(self, binary, spaces, CXPB=0.6, MUTPBI=0.1, MUTPBII=0.1, maxGeneration=50):
        self.binary = binary
        self.spaces = spaces
        self.original_binary = binary + "_original"
        shutil.copy(binary, self.original_binary)

        self.best_fitness_per_g = []
        self.undetected = False
        self.best_individual = None
        self.best_pred = 1.0
        self.maxGeneration = maxGeneration

        self.toolbox = base.Toolbox()
        self.CXPB = CXPB
        self.MUTPBI = MUTPBI
        self.MUTPBII = MUTPBII

    def register_tools(self):
        length_individual = self.size_array_of_spaces()
        if not hasattr(creator, "FitnessMax"): creator.create("FitnessMax", base.Fitness, weights=(1.0,))
        if not hasattr(creator, "Individual"): creator.create("Individual", list, fitness=creator.FitnessMax)

        self.toolbox.register("attr_bool", random.randint, 0, 255)                                                           # Attribute (gene) is a byte
        self.toolbox.register("individual", tools.initRepeat, creator.Individual, self.toolbox.attr_bool, length_individual) # Individual is a byte vector
        self.toolbox.register("population", tools.initRepeat, list, self.toolbox.individual)                                 # Population is a list of individuals

        self.toolbox.register("evaluate", self.fitness_individual)                    # Fitness evaluation function
        self.toolbox.register("crossover", self.crossover)                            # Crossover function
        self.toolbox.register("mutate", self.mutate, indpb=self.MUTPBII)              # Mutation function (MUTPBII for gene-level mutation)
        self.toolbox.register("select_elitism", tools.selBest)                        # Elitism selection function
        self.toolbox.register("select_tournament", tools.selTournament, tournsize=10) # Tournament selection function

    def unregister_tools(self):
        self.toolbox.unregister("attr_bool")
        self.toolbox.unregister("individual")
        self.toolbox.unregister("population")
        self.toolbox.unregister("evaluate")
        self.toolbox.unregister("mutate")
        self.toolbox.unregister("select_elitism")
        self.toolbox.unregister("select_tournament")

    def optimize(self, population_size=10, block_size=32):
        ELITISM_COUNT = 5    # Elitism group count
        TOURNAMENT_COUNT = 5 # Tournament group count
        TOURNAMENT_SIZE = 10 # Tournament selection participant

        self.register_tools()                       # Tools registration

        population = self.toolbox.population(n=population_size) # Initial population
        fitnesses = list(map(self.toolbox.evaluate, population))       # Initial fitness evaluation
        for ind, fit in zip(population, fitnesses): 
            ind.fitness.values = fit
        fits = [ind.fitness.values[0] for ind in population]
        self.best_fitness_per_g.append(1 - max(fits))           # Best malware probability tracking: 1 - max(fitness_val)

        generationIdx = 0
        while self.check_continue(generationIdx):
            logging.info(f"--- Generation {generationIdx} for {self.binary} ---")
            
            # Elitism group selection
            elitism_group = list(map(self.toolbox.clone, tools.selBest(population, ELITISM_COUNT)))
            for ind in elitism_group:
                population.remove(ind)
            
            # Tournament group selection
            tournament_group = list()
            while len(tournament_group) < TOURNAMENT_COUNT:
                ind = list(map(self.toolbox.clone, tools.selTournament(population, 1, tournsize=TOURNAMENT_SIZE)))
                population.remove(ind[0])
                tournament_group.append(ind[0])

            # Crossover sequence
            offspring = list()
            for elitist_ind in elitism_group:
                for tournament_ind in tournament_group:
                    mate_1 = self.toolbox.clone(elitist_ind)
                    mate_2 = self.toolbox.clone(tournament_ind)

                    if random.random() < self.CXPB:
                        curr_offspring = self.toolbox.crossover(mate_1, mate_2, 2, block_size)
                    else:
                        curr_offspring = [mate_1, mate_2]
                        for child in curr_offspring:
                            del child.fitness.values

                    for mate_offspring in curr_offspring:
                        offspring.append(mate_offspring)
            logging.debug(f"Crossover sequence complete with offspring length: {len(offspring)}")

            # Mutation sequence
            offspring = list(map(self.toolbox.clone, offspring))
            offspring_mut = list()
            for mutant in offspring:
                if random.random() < self.MUTPBI:
                    mutant = self.toolbox.mutate(mutant)
                offspring_mut.append(mutant)
            logging.debug(f"Mutation sequence complete.")

            # Fitness reevaluation
            offspring = list(map(self.toolbox.clone, offspring_mut))
            invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
            fitnesses = map(self.toolbox.evaluate, invalid_ind)
            for ind, fit in zip(invalid_ind, fitnesses):
                ind.fitness.values = fit
            logging.debug(f"Fitness reevaluation completed.")

            population = tools.selBest(offspring, population_size - 1) # Select top k-1 offsprings
            for ind in tools.selBest(elitism_group, 1):                # Select best ind from elitism_group
                population.append(ind)                                 # Total population = population_size

            best = tools.selBest(population, 1)[0] # Select best ind from population
            best_mod = self.local_hill_climb(best) # Hill climb for the best individual
            population.remove(best)
            population.append(best_mod)

            del fitnesses
            del offspring
            del offspring_mut
            del elitism_group
            del tournament_group
            logging.debug(f"Initialized new population with length: {len(population)}")

            fits = [ind.fitness.values[0] for ind in population] # Get all fitness scores
            self.best_fitness_per_g.append(1 - max(fits))        # Save best pred value (1 - fitness value)
            length = len(population)                             # Population length
            mean = sum(fits) / length                            # Average fitness score
            sum2 = sum(x * x for x in fits)                      
            std = abs(sum2 / length - mean ** 2) ** 0.5          # Std deviation of fitness scores

            logging.info("  Length " + str(length))              # Logging data
            logging.info("  Min %s" % (1 - max(fits)))
            logging.info("  Max %s" % (1 - min(fits)))
            logging.info("  Avg %s" % (1 - mean))
            logging.info("  Std %s" % std)

            generationIdx += 1                                   # Increment generationIdx

        if self.undetected:
            logging.info("[*] Evasion achieved!")
        self.unregister_tools()
        self.restore_best_one()
        os.remove(self.original_binary)

        return generationIdx, self.undetected
    
    def check_continue(self, generationIdx):
        if self.undetected: return False                       # Exit if undetected
        elif generationIdx >= self.maxGeneration: return False # Exit if exceeded max generation
        elif generationIdx >= 10 and (                         # Exit if stagnation / premature convg
            self.best_fitness_per_g[-10] - self.best_fitness_per_g[-1] < 0.01
        ): return False
        else: return True

    def mutate(self, individual, indpb):
        mutation_count = round(len(individual) * indpb)                            # Calculate the amount of genes to mutate
        mutation_target = random.sample(range(0, len(individual)), k=mutation_count) # Determine which gene to mutate
        for i in range(mutation_count):
            individual[mutation_target[i]] = random.randint(0, 255)                  # Reroll gene's byte value
        return individual
    
    def crossover(self, ind1, ind2, offspring_count, block_size):
        curr_offspring = list()
        fitness_1 = 1 - ind1.fitness.values[0]
        fitness_2 = 1 - ind2.fitness.values[0]
        
        prob = 0
        if fitness_1 + fitness_2 != 0:
            prob = 1 - (fitness_1 / (fitness_1 + fitness_2)) # Higher probability to copy from better parent
        if prob is None or prob <= 0 or prob >= 1:
            prob = 0.5                                       # Fallback probability value
        
        for i in range(offspring_count):
            curr_individual = self.toolbox.clone(ind1)
            del curr_individual.fitness.values
            counter = 0

            while counter < len(ind1):
                size_data = min(block_size, len(ind1) - counter) # Data to get from parent
                if random.random() < prob:                       # Get block from ind1
                    curr_individual[counter:(counter + size_data)] = ind1[counter:(counter + size_data)]
                else:                                            # Get block from ind2
                    curr_individual[counter:(counter + size_data)] = ind2[counter:(counter + size_data)]
                counter += size_data
            
            curr_offspring.append(curr_individual)
        return curr_offspring
    
    def local_hill_climb(self, individual, steps=50, radius=8):
        best = self.toolbox.clone(individual)
        best_fit = best.fitness.values[0]

        for _ in range(steps):
            candidate = self.toolbox.clone(best)
            positions = random.sample(range(len(candidate)), k=radius) # Get k random positions
            for pos in positions:
                candidate[pos] = random.randint(0, 255)                # Reroll bytes in positions
            
            curr_fit = self.toolbox.evaluate(candidate)[0]             # Evaluate current candidate
            candidate.fitness.values = (curr_fit,)                     # Update candidate's fitness score

            if curr_fit > best_fit:
                best = self.toolbox.clone(candidate)                   # Update best candidate
                best_fit = curr_fit                                    # Update best fit

                if self.undetected:                              # Early break if undetected
                    break 
        return best                                                    # Return the best candidate

    def write_on_spaces_mmap(self, pop):
        try:
            f = open(self.binary, "r+b")
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
            mm.flush()

            counter = 0
            for expand in self.spaces['expand']:
                if self.spaces['expand'][expand]['size'] > 0 and self.spaces['expand'][expand]['start_p_address'] > 0:
                    data = pop[counter:(counter + self.spaces['expand'][expand]['size'])]
                    size_data = self.spaces['expand'][expand]['size']
                    counter += size_data
                    data = bytes(data)
                    address = self.spaces['expand'][expand]['start_p_address']
                    mm.seek(address)
                    written_bytes = mm.write(data)
                    if written_bytes != len(data):
                        logging.error("Error when writing data on the binary (data length [" + str(
                            len(data)) + "] != written bytes [" + str(written_bytes) + "]")

            mm.flush()
            mm.close()
            f.close()
        except Exception as e:
            logging.error(e)

    def size_array_of_spaces(self):
        size = 0
        for expand in self.spaces['expand']: size += self.spaces['expand'][expand]['size']
        return size

    def fitness_individual(self, individual):
        shutil.copy(self.original_binary, self.binary)
        self.write_on_spaces_mmap(individual)
        pred = getPredictionScore(self.binary)
        if pred < self.best_pred:
            self.best_pred = pred 
            self.save_best_one(individual)
            if self.best_pred < 0.5:
                self.undetected = True

        return (1-pred,)

    def save_best_one(self, individual):
        self.best_individual = individual

    def restore_best_one(self):
        shutil.copy(self.original_binary, self.binary)
        self.write_on_spaces_mmap(self.best_individual)

def getPredictionScore(filepath):
    return model.predict(filepath)

def main(binary):
    try:
        with Timeout(1800):
            logging.info(f"Target PE: {binary}")
            cpu_time = time.perf_counter()  # Log CPU start time
            success = False
            sizeRatio = INIT_SIZE_RATIO     # Initial size set to 1% of binary length (Enchancing AEs paper uses 257 bytes as static size, original paper uses 1% as starting size)

            while not success and sizeRatio <= 100:
                with Timeout(900):
                    logging.info(f"[*] Trying with size {sizeRatio}%")
                    shutil.copy(binary, f"{binary}_inc")

                    r2 = r2_bind(f"{binary}_inc")
                    logging.info("[+] Checkpoint 1")
                    spaces = r2.main(sizeRatio, -1)
                    logging.info("[+] Checkpoint 2")
                    try: r2.close()
                    except: pass 
                    logging.info("[+] Checkpoint 3")
                if spaces["expand"] is None:
                    print(f"[!] Expansion failure occured")               # Cave expansion failure case, exit immediately
                    success = True 
                    generation = 9999999999999999
                    sizeRatio = 9999999999999999
                else:
                    logging.info("[+] Checkpoint 4")
                    optimizer = MemeticOptimizer(f"{binary}_inc", spaces) # MemeticOptimizer initialization
                    generation, success = optimizer.optimize()
                
                if not success:
                    logging.info(f"[-] Unsuccessful with size {sizeRatio}%")
                    shutil.copy(binary, f"{binary}_inc")
                    if sizeRatio < 15: sizeRatio += 3  # Increment ratio by 3 percent
                    else: sizeRatio += 10              # Increment ratio by 10 percent
            
            if not success:                            # Failure scenario
                logging.info("[-] Successful AE is not found")
                os.remove(f"{binary}_inc")
            else:                                      # Success scenario
                logging.info("[*] Successful AE found!")
                shutil.copy(f"{binary}_inc", f"{binary}")
                os.remove(f"{binary}_inc")
            
            cpu_time = time.perf_counter() - cpu_time  # Calculate time elapsed
            logging.info(f"[*] Generation: {generation}")
            logging.info(f"[*] Time elapsed: {cpu_time}")
            logging.info(f"[*] Size ratio: {INIT_SIZE_RATIO}/{sizeRatio}")
    
    except NotPE:
        logging.error(f"{binary} is not a valid PE file")
    except Timeout.TimeoutError:
        logging.error("Timeout")
    except Exception as e:
        logging.exception("An unexpected error has occured")
    finally:
        if os.path.exists(f"{binary}_inc"): 
            os.remove(f"{binary}_inc")             # Remove leftover copies
        if os.path.exists(f"{binary}_inc_original"): 
            os.remove(f"{binary}_inc_original")    # Remove leftover copies

if __name__ == '__main__':
    main(args.file_path)
