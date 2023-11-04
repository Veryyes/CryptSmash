from __future__ import annotations
from typing import Type, Tuple
import os
import json
from math import log10

import magic

from cryptsmash.utils import data_dir, chi_squared, frequency_table
#############################################
# Attempt Decryption with all Keys and Rank #
#############################################
# All ASCII -> Good (But not Bad thing if it isnt)
# Python Magic detects a non-data file -> Good
# Language Score

# def detect_decryption(decrypted_data:bytes, key):
    # known_file, file_type = is_known_file(decrypted_data)
    # if known_file:
    #     return True
# def decrypt_score(decrypted_data:bytes, key):
#     score = 1

#     # known_file, file_type = is_known_file(decrypted_data)
#     # if known_file:
#     #     score *= 
    
#     eng_fitness = quadgram_fitness(decrypted_data, English)
#     eng_similiarity = chi_squared(frequency_table(decrypted_data))
#     printable_percentage(decrypted_data)

def fitness(key:bytes, key_score:float, cipher_text:bytes, decrypt:Callable[[bytes, bytes], bytes]):
    plain_txt = decrypt(cipher_text, key)

    if key_score == 0:
        key_score = .0001

    score = key_score
    known_file, file_type = is_known_file(plain_txt)
    if known_file:
        score  *= .99
    else:
        score *= .005

    eng_fitness = quadgram_fitness(plain_txt.upper(), English)
    eng_similiarity = chi_squared(frequency_table(plain_txt), English.byte_distro, len(plain_txt))
    printable_percent = printable_percentage(plain_txt)

    score *= eng_fitness * eng_similiarity * printable_percent
    score = score**(1/5)

    return (plain_txt, key, file_type, eng_fitness, eng_similiarity, printable_percent, score)


def printable_percentage(data:bytes) -> float:
    '''
    Returns the percentage of bytes that are printable
    '''
    count = 0
    for b in data:
        # num = int.from_bytes(b, 'little')
        if b >= 32 and b <= 126:
            count += 1

    return count / len(data)

def quadgram_fitness(data:bytes, lang:Type[Language]) -> float:
    score = 0
    for i in range(len(data) - 3):
        score += lang.quadgrams.get(data[i:i+4], log10(1 + (0.01/lang.quadgram_total)))
    return score / (len(data)/4)

def is_known_file(data:bytes) -> Tuple[bool, str]:
    _type = magic.from_buffer(data[:2048]).strip()
    return _type != "data", _type

class Language:
    ENCODING = "UTF8"
    byte_distro:Dict[int, float]
    quadgrams:Dict[bytes, int]
    quadgram_total:int = 1

class English(Language):
    '''English Specific Statistics'''

    ENCODING = "UTF8"
    
    # Byte Distribution
    byte_distro = dict()
    with open(os.path.join(data_dir(), "english_stats.json"), 'r') as f:
        byte_distro = json.load(f)
    for i in range(256):
        byte_distro[int.to_bytes(i, length=1, byteorder='little')] = byte_distro[str(i)]
        del byte_distro[str(i)]

    # 4 UTF8 Grams Scores
    quadgrams = dict()
    with open(os.path.join(data_dir(), "english_quadgrams.txt"), 'r') as f:
        while (line := f.readline()):
            key, count = line.split(' ')
            quadgrams[bytes(key.strip(), ENCODING)] = float(count)

    quadgram_total = sum(quadgrams.values())
    for key in quadgrams.keys():
        quadgrams[key] = log10(1 + (quadgrams[key] / quadgram_total))