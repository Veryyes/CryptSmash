import math
from typing import IO
from multiprocessing import Pool, shared_memory

from rich.progress import Progress


from cryptsmash.utils import read_blks

def key_in_nulls(f:IO, size:int, suspect_key_len:int=0, block_size=4096, num_cores=None, verbose=True):
    '''
    Look for repeated bytes where NULL bytes could have been in the plaintext
    :param f: the IO stream to the file to attack
    :param size: the length of the file in bytes
    :oaram suspect_key_len: The suspected key length. Leave as 0 if unknown
    :param block_size: the number of bytes to process at a single time
    :param num_cores: number of cores to run with. Leave at 0 for all cores
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


# stole from https://medium.com/datascienceray/longest-repeated-substring-a6bb7722d73c
def lrs(data:bytes, progress=None, task_id=None):
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