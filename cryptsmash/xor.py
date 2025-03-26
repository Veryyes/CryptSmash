'''
Attack XOR Ciphers
Based on Known Plaintext Attacks and Statisical Properties of Plaintext
'''
import os
import json
import math
import itertools
import queue
from typing import IO, List, Dict, Tuple
from collections import defaultdict
from multiprocessing import Pool

from rich import print
from rich.table import Table
from rich.console import Group
from rich.prompt import Prompt
from rich import progress
import numpy as np

from cryptsmash.utils import rich_map, data_dir
from cryptsmash.plaintext import fitness, fitness_multiproc

def encrypt(data:bytes, key:bytes):
    return xor(data, key)

def decrypt(data:bytes, key:bytes):
    return xor(data, key)

def xor(data:bytes, key:bytes):
    return bytes(d ^ k for d, k in zip(data, itertools.cycle(key)))

# def polyalphabetic_keylen_detection(f:IO, num_cores=None, max_key_len=32):
#     start = time.time()
#     data = f.read()
#     min_key_len = 1    

#     periods = list()
#     for key_len in range(min_key_len, max_key_len):
#         freq = defaultdict(lambda: defaultdict(lambda: 0))
#         for i, b in enumerate(data):
#             i = i % key_len
#             freq[i][b] += 1

#         iocs = list()
#         for i in range(key_len):
#             numerator = 0
#             denominiator = len(data) * (len(data) - 1)
#             for count in freq[i].values():
#                 numerator += (count * (count - 1))

#             iocs.append(numerator/denominiator)

#         periods.append(np.average(np.array(iocs)))

#     print(time.time() - start)
#     print(np.argmax(periods)+1)
#     scatter(x=list(range(len(periods))), y=periods)
#     scatter(x=[np.argmax(periods)], y=max(periods), marker='^')
#     plt.show()

def _coincidence_score(data, key_len, max_key_len, progress=None, task_id=None):
    cur = 0
    total = len(data) + key_len

    freq = defaultdict(lambda: defaultdict(lambda: 0))
    for i, b in enumerate(data):
        key_idx = i % key_len
        freq[key_idx][b] += 1

        if progress is not None and i%2048 == 0:
            cur += 2048
            progress[task_id] = {'progress': min(cur, len(data)), 'total':total}

    if progress is not None:
        cur = len(data)
        progress[task_id] = {'progress': cur, 'total':total}
        
    score = 0
    for i in range(key_len):
        score += max(freq[i].values()) - 1
    
    score = score / (max_key_len + key_len**1.5)

    if progress is not None:
        progress[task_id] = {'progress': total, 'total':total}

    return score

def _find_repeats(data:bytes):
    '''
    Returns a bytearray that repeats in data and starts at data[0]
    '''
    for i, char in enumerate(data):
        prefix = data[:i+1]
        if prefix not in data[i+2:]:
            repeated = data[:-len(prefix) + 1]
            if len(repeated) == 0:
                return data
            return repeated

def _reduce_repeats(data:bytes):
    '''Returns the smallest bytearray that repeats in data and starts at data[0]'''
    prev = None
    while prev != data:
        prev = data
        data = _find_repeats(data)
    return data

def detect_key_length(ctxt:bytes, num_cores=None, max_key_len=32, n:int=10, verbose=True):
    '''
    Detect Key Length by measuring the number of coincidences for each possible key length
    Then looking at local maximum -> Should expect peaks at multiples of the key size
    Based on xortool's key length detection
    '''
    max_key_len += 1
    min_key_len = 1

    if max_key_len - min_key_len == 1:
        return (1, 1) 

    maximums = list()

    scores = rich_map(
        _coincidence_score, 
        ((ctxt, key_len, max_key_len) for key_len in range(min_key_len, max_key_len)), 
        total=max_key_len - min_key_len,
        job_title="Scoring Possible Key Sizes",
        disabled=not verbose
    )

    if scores[0] > scores[1]:
        maximums.append((1, scores[0]))

    for i in range(1, len(scores)):
        # Next index goes over
        if i+1 == len(scores):
            if scores[i-1] < scores[i]:
                maximums.append((i+1, scores[i]))
        else:
            if scores[i-1] < scores[i] and scores[i] > scores[i+1]:
                maximums.append((i+1, scores[i]))

    # Normalize 
    total = sum((x[1] for x in maximums))
    for i in range(len(maximums)):
        key_len, score = maximums[i]
        maximums[i] = (key_len, score/total)

    if n is None:
        return sorted(maximums, key=lambda x:x[1], reverse=True)

    return sorted(maximums, key=lambda x:x[1], reverse=True)[:n]


class ProgressTable(progress.Progress):
    def get_renderables(self):
        table = Table()
        table.add_column("Score")
        table.add_column("Candidate Key")

        for task in self.tasks:
            for i, state in enumerate(sorted(task.fields['table'])):
                if i == task.fields['top_n']:
                    break

                score, base_key = state
                table.add_row(
                    "{:.4f}".format(-score),
                    str(base_key)[2:-1]
                )
            yield Group(self.make_tasks_table(self.tasks), table)

def known_plaintext_prefix(
    ctxt:bytes, 
    known_prefix:bytes,
    candidate_key_lens:List[Tuple[int, float]],
    key_max_length:int=64,
    top_n=10,
) -> Tuple[bytes, bool]:
    '''
    Partial or Full Key recovery based on a known plaintext prefix
    Usually in CTFs, the known_prefix is 'flag{'
    :param f: the IO stream to the file to attack
    :param known_prefix: The known first several bytes in the plaintext
    :returns: If the boolean is True then the bytes are the key, Otherwise the bytes are the start of the key
    '''
    # We get partial/full key with by decrypting the first len(known_prefix) bytes
    # If true key len <= len(known_prefix) -> Full Key Recovered
    # if true key len > len(known_prefix) -> Partial Key Recovered
    repeated_key = xor(ctxt[:len(known_prefix)], known_prefix)

    # "reduce" out repeated keys
    simplified_key = _reduce_repeats(repeated_key)

    # The case where the key has repeated itself or started to repeat itself 
    if len(repeated_key) > len(simplified_key):
        return simplified_key, True

    # The case where we have the partial key, or the entire key itself exactly
    key_score_lookup = defaultdict(lambda: min(candidate_key_lens, key=lambda x:x[1])[1])
    for key_len, score in candidate_key_lens:
        key_score_lookup[key_len] = score     

    # Try to rebuild the plaintext and score guessed plaintexts
    cipher_txt = ctxt[:2048]
    keys = queue.PriorityQueue()
    s = fitness(simplified_key, key_score_lookup[len(simplified_key)], cipher_txt, xor)
    keys.put((-s.score, simplified_key))

    run_for = key_max_length - len(simplified_key)
    with Pool() as p:
        with ProgressTable() as progress_bar:
            explored = []
            task = progress_bar.add_task("Trying to interpolate partial key...", total=run_for, table=explored, top_n=top_n)
            for _ in range(run_for):
                explore_key = False
                while not explore_key:
                    if keys.empty():
                        break

                    score, base_key = keys.get()
                    explored.append((score, base_key))

                    if len(base_key) <= key_max_length:
                        explore_key = True        
                        
                if not explore_key:
                    progress_bar.update(task, completed=True)
                    break

                for new_scores in p.imap(
                    fitness_multiproc,
                    ((base_key + int.to_bytes(b, 1, 'little'), key_score_lookup[len(base_key)+1], cipher_txt, xor) for b in range(255))
                ):
                    keys.put((-new_scores.score, new_scores.key))

                progress_bar.update(task, advance=1, table=explored, top_n=top_n)

    # Place all the explored states back in the queue
    # to select the best out of all possible states explored
    for e in explored:
        keys.put(e)

    # _, best = keys.get()
    best = []
    for i in range(top_n):
        _, key = keys.get()
        best.append(key)

    return best, False


def key_in_nulls(
    ctxt:bytes,
    size:int, 
    suspect_key_len:int=0, 
    block_size=4096, 
    num_cores=None, 
    verbose=True
):
    '''
    Look for repeated bytes where NULL bytes could have been in the plaintext
    :param f: the IO stream to the file to attack
    :param size: the length of the file in bytes
    :param suspect_key_len: The suspected key length. Leave as 0 if unknown
    :param block_size: the number of bytes to process at a single time
    :param num_cores: number of cores to run with. Leave at 0 for all cores
    :returns: Potential Keys
    '''
    total=math.ceil(size/block_size)
    with Pool(num_cores) as p:
        with progress.Progress(disable=not verbose) as progress_bar:
            task_id = progress_bar.add_task("Longest Repeated Substring of Bytes", total=total)
            
            # Find the largest repeating substrings in blocks of data
            repeated_substrs = set()
            for substr in p.imap(lrs, [ctxt[i:i+block_size] for i in range(0, len(ctxt), block_size)]):
                repeated_substrs.add(substr)
                progress_bar.advance(task_id)
        
        # If we have a suspected key length, keep strings that are greater than or equal to the (known) key length
        if suspect_key_len > 0:
            repeated_substrs = filter(lambda substr: len(substr) >= suspect_key_len, repeated_substrs)
        
        # cleans out stuff that doesnt repeat
        # I think its probable that the key is repeated in one of the strings in repeated_substrs
        # converting to a list improves performances when pruneing empty strings for some reason
        repeated_substrs = list(p.imap(lrs, repeated_substrs))

    # Remove empty Strings
    repeated_substrs = list(filter(lambda substr: len(substr) != 0, repeated_substrs))

    possible_keys = set([])
    for s in repeated_substrs:
        # Check if string repeats itself (key probably shows up several times in s)
        maybe_key = repeats(s)
        if maybe_key:
            for rotated_key in rotations(maybe_key):
                possible_keys.add(rotated_key)

    return list(possible_keys)


def file_header_key_extract(ctxt:bytes, headers:List[bytes]):
    '''
    Attempts XOR against several file headers hoping the headers are the known plaintext in the case where a whole file is XOR encrypted
    :param f: the IO stream to the file to attack
    :returns: Potential Keys
    '''
    block_size=2048
    cipher_text = ctxt[:block_size]

    maybe_keys = list()
    for header in headers:
        key_block = xor(header, cipher_text)

    maybe_keys.append(lrs(key_block))

    maybe_keys = [repeats(k) for k in maybe_keys]
    maybe_keys = [rotations(k) for k in maybe_keys if k]

    # unflatten the nested list
    return list(itertools.chain(*maybe_keys))

def _stat_attack_helper(
    data:bytes, 
    key_length:int, 
    byte_distro:Dict[int,float], 
    progress=None, task_id=None
):
    total = len(data) + key_length + key_length*256*256
    cur = 0
    frequencies = np.zeros((key_length, 256))
    sum_sqrs = np.sum(np.square(list(byte_distro.values())))

    # Grab the frequency of bytes for each position in the cipher text where
    # the same index of the key is xor'd against
    for i in range(len(data)):
        b = data[i]
        frequencies[i%key_length][b] += 1
        
        if progress is not None and i%512==0:
            cur += 512
            progress[task_id] = {"progress": cur, "total": total}

    if progress is not None:
        cur = len(data)
        progress[task_id] = {"progress": cur, "total": total}

    # Normalize the frequency table to a prob distribution
    for i in range(key_length):
        stream_count = np.sum(frequencies[i])
        frequencies[i] = frequencies[i]/stream_count

    if progress is not None:
        cur += key_length
        progress[task_id] = {"progress":cur, "total": total}

    # For byte in the key, we will try to find the value that matches up against
    # the closest to the sum squared value of that byte in the byte_distro
    key = list()
    for i in range(key_length):
        best_cost = 10**9
        best = b'\x00'

        for test in range(256):
            total = 0
            for b in range(256):
                total += byte_distro[b] + frequencies[i][(b ^ test)]


            cost = abs(total - sum_sqrs)
            if cost < best_cost:
                best_cost = cost
                best = test

            if progress is not None:
                cur += 256
                progress[task_id] = {"progress": cur, "total": total}

        key.append(best)

    # Byte order doesn't matter here
    return b''.join([int.to_bytes(k, length=1, byteorder='little') for k in key])

def known_plaintext_statistical_attack(
    ctxt:bytes,
    byte_distro:Dict[int,float], 
    suspect_key_len=0, 
    max_key_len=32, 
    num_cores=None, 
    verbose=True
):
    '''
    Attempt to extract the key based on knowning the underlying distribution of the bytes of the plain text. This is the same as breaking a vigenere cipher, but with bytes
    
    ''' 
    keys = list()

    max_key_len += 1
    min_key_len = 1
    
    if suspect_key_len > 0:
        min_key_len = suspect_key_len
        max_key_len = suspect_key_len+1

    # Multiprocess against each possible key length we guess
    for key in rich_map(
        _stat_attack_helper, 
        ((ctxt, key_len, byte_distro) for key_len in range(min_key_len, max_key_len)), 
        total=max_key_len-min_key_len,
        job_title="Statistical Vigenere-style Attack",
        disabled=not verbose,
    ):
        
        keys.append(key)

    return keys
    

# stole from https://medium.com/datascienceray/longest-repeated-substring-a6bb7722d73c
def lrs(data:bytes, progress=None, task_id=None):
    '''
    Longest Repeated Substring
    '''
    data_size=len(data)

    suffix = list()
    for i in range(data_size):
        suffix.append(data[data_size-i-1:data_size])

        # Progress Bar
        if progress is not None:
            progress[task_id] = {"progress": i, "total": data_size*2}
    suffix = sorted(suffix)
    
    lrs=b""
    length=0
    for i in range(data_size-1):
        length = lcp(suffix[i], suffix[i+1], len(lrs))
        if length > len(lrs):
            lrs = suffix[i][0:length]

        # Progress Bar
        if progress is not None:
            progress[task_id] = {"progress": data_size+i, "total": data_size*2}
    
    return lrs

# also stole from https://medium.com/datascienceray/longest-repeated-substring-a6bb7722d73c
def lcp(s1,s2,current_len):
    # I think this stands for longest common prefix?

    if(len(s1)<len(s2)):
        limit=len(s1)
    else:
        limit=len(s2)

    
    if(s1[0:limit]==s2[0:limit]): # if substring are the same at limit, return limit
        return limit
    
    if(limit < current_len):      # if the limit is less than the length of current duplicated substring, we don't need to 
        return 0                  # compare.
    else:
        n = current_len
        while(s1[0:n+1]==s2[0:n+1] and n<=limit):
            n+=1
        
        if(n>current_len):
            return n
        else:
            return 0  

def repeats(s):
    '''
    if s has a substring the repeats itself, return that substring else return None
    '''
    temp = (s + s).find(s, 1, -1)
    if temp != -1:
        return s[:temp]
    return None

def rotations(s):
    yield s
    for i in range(1, len(s)+1):
        yield s[-i:] + s[:-i]

def smash(ctxt:bytes, ptxt_prefix=None, verbose=False, console=None):

    # If the first few bytes of the plaintext are known,
    # calculate the part of the key corresponding to the known bytes
    key_prefix = None
    if ptxt_prefix:
        ptxt_prefix = bytes(ptxt_prefix, 'ascii')
        key_prefix = xor(ctxt[:len(ptxt_prefix)], ptxt_prefix)

    # Score possible Key Sizes
    if verbose:
        console.log("[bold green]Calculating Possible Key Lengths")
    key_lens = detect_key_length(ctxt, max_key_len=64, n=None, verbose=verbose)
    if verbose:    
        table = Table(title=f"Top 10 Most Probably Key Lengths")
        table.add_column("Key Length")
        table.add_column("Probability")
        for key_len, prob in key_lens[:10]:
            table.add_row(str(key_len), "{:.2f}%".format(prob*100))
        print(table)

    # Greedy Search using the Known Plaintext as a seed state
    candidate_key = None
    if ptxt_prefix:
        candidate_key, full_recovery = known_plaintext_prefix(ctxt, ptxt_prefix, key_lens)
        if full_recovery:
            full_key = candidate_key
            keep_going = Prompt.ask(f"Found Key \"{full_key}\", Continue Analysis? (y/n)", choices=['y', 'n'], default='y')
            if keep_going == 'n':
                console.log(key_prefix)
                return
        else:
            print(f"Found Partial Keys: {candidate_key}")
    
    # Create a set of all possible bytearrays we think could be keys
    ptxt_len = len(ctxt)

    candidate_keys = set()
    if isinstance(candidate_key, list):
        candidate_keys |= set(candidate_key)
    elif candidate_key:
        candidate_keys.add(candidate_key)

    ###################
    # All 1 Byte Keys #
    ###################
    if verbose:
        console.log("[bold green]Brute forcing all 1 Byte keys")
    candidate_keys |= set([int.to_bytes(x, length=1, byteorder='little') for x in range(255)])

    ####################
    # Check NULL Bytes #
    ####################
    if verbose:
        console.log("[bold green]Looking for XOR key in Plaintext NULL bytes")

    candidate_keys |= set(key_in_nulls(ctxt, size=ptxt_len, verbose=verbose))
    
    ##########################################
    # Try File Headers as Partial Plain Text #
    ##########################################
    if verbose:
        console.log("[bold green]Known Plaintext Attack w/ Known File Headers")

    headers = list()
    example_dir = os.path.join(data_dir(), "example_files")
    for filename in os.listdir(example_dir):
        filepath = os.path.join(example_dir, filename)
        with open(filepath, 'rb') as example_f:
            headers.append(example_f.read(2048))
    candidate_keys |= set(file_header_key_extract(ctxt, headers))
    
    ###################################
    # Language Frequency Based Attack #
    ###################################
    if verbose:
        console.log("[bold green]Statistical attack against English")

    with open(os.path.join(data_dir(), "english_stats.json"), 'r') as sf:
        lang_data = json.load(sf)
        if "byte_distrib" not in lang_data:
            raise ValueError("Expecting a \'byte_distrib\' -> Dict[str, float] mapping lang_data") 
        byte_distro = lang_data["byte_distrib"]
        # Nuance with Loading a Dict with Int as Keys
        for i in range(256):
            byte_distro[i] = byte_distro[str(i)]
            del byte_distro[str(i)]
        
        candidate_keys |= set(known_plaintext_statistical_attack(ctxt, byte_distro))

    ##########################################
    # Rank Keys Based on Candidate Key Sizes #
    ##########################################
    key_weights = dict(key_lens)
    keys = list()
    key_scores = list()
    for key in candidate_keys:
        if len(key) in key_weights:
            keys.append(key)
            key_scores.append(key_weights[len(key)])

    return keys, key_scores, key_prefix
