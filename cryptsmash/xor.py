'''
Attack XOR Ciphers
Based on Known Plaintext Attacks and Statisical Properties of Plaintext
'''

import math
import itertools
from typing import IO, List, Dict
from multiprocessing import Pool, shared_memory

from rich.progress import Progress
import numpy as np

from cryptsmash.utils import read_blks, rich_map

def xor(data:bytes, key:bytes):
    return bytes(d ^ k for d, k in zip(data, itertools.cycle(key)))

def key_in_nulls(f:IO, size:int, suspect_key_len:int=0, block_size=4096, num_cores=None, verbose=True):
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
    with Pool() as p:
        with Progress(disable=not verbose) as progress:
            task_id = progress.add_task("Longest Repeated Substring of Bytes", total=total)
            
            # Find the largest repeating substrings in blocks of data
            repeated_substrs = set()
            for substr in p.imap(lrs, read_blks(f, block_size)):
                repeated_substrs.add(substr)
                progress.advance(task_id)
        
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


def file_header_key_extract(f:IO, headers:List[bytes]):
    '''
    Attempts XOR against several file headers hoping the headers are the known plaintext in the case where a whole file is XOR encrypted
    :param f: the IO stream to the file to attack
    :returns: Potential Keys
    '''
    block_size=2048
    cipher_text = f.read(block_size)

    maybe_keys = list()
    for header in headers:
        key_block = xor(header, cipher_text)

    maybe_keys.append(lrs(key_block))

    maybe_keys = [repeats(k) for k in maybe_keys]
    maybe_keys = [rotations(k) for k in maybe_keys if k]

    # unflatten the nested list
    return list(itertools.chain(*maybe_keys))

def _stat_attack_helper(data:bytes, key_length:int, byte_distro:Dict[int,float], progress=None, task_id=None):
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

def known_plaintext_statistical_attack(f:IO, byte_distro:Dict[int,float], suspect_key_len=0, max_key_len=32, num_cores=None, verbose=True):
    '''
    Attempt to extract the key based on knowning the underlying distribution of the bytes of the plain text. This is the same as breaking a vigenere cipher, but with bytes
    
    '''
    data = f.read()   
    keys = list()

    min_key_len = 1
    
    if suspect_key_len > 0:
        min_key_len = suspect_key_len
        max_key_len = suspect_key_len+1

    # Multiprocess against each possible key length we guess
    for key in rich_map(
        _stat_attack_helper, 
        ((data, key_len, byte_distro) for key_len in range(min_key_len, max_key_len)), 
        total=max_key_len-min_key_len,
        job_title="Statistical Vigenere Attack"
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
    
    lrs=""
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