from typing import Tuple, Iterable
import string

import numpy as np

def _param_check(key:Tuple[int, int], alphabet:Iterable):
    if len(key) != 2:
        raise ValueError("key must be a tuple of 2 integers (a, b)")

    a, _ = key
    if not np.gcd(a, len(alphabet)):
        raise ValueError("a must be co-prime with the alphabet size") 

def encrypt(ptxt:str, key:Tuple[int, int], alphabet:Iterable=string.ascii_lowercase):
    _param_check(key, alphabet)
    
    a, b = key
    cipher = list()
    for p in ptxt:
        ordinal_value = alphabet.index(p)
        cipher.append(alphabet[(a*ordinal_value+b)%len(alphabet)])
    return ''.join(cipher)

def decrypt(ctxt:str, key:Tuple[int, int], alphabet:Iterable=string.ascii_lowercase):
    _param_check(key, alphabet)

    a, b = key

    a_inv = pow(a, -1, len(alphabet))
    plain = list()
    for c in ctxt:
        # Skips non alphabet chars
        if c in alphabet:
            ordinal = alphabet.index(c)
            plain.append(alphabet[(ordinal-b)*a_inv % len(alphabet)])
    return ''.join(plain)

def smash(ctxt:str, alphabet:Iterable=string.ascii_lowercase):
    keys = list()
    for a in range(len(alphabet)):
        if np.gcd(a, len(alphabet)) != 1:
            continue
        for b in range(len(alphabet)):
            keys.append((a, b))

    return keys