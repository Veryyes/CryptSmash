from __future__ import annotations
from typing import Type, Tuple, Callable, Union, List
import os
import json
from math import log10
from multiprocessing import Pool
from dataclasses import dataclass

import magic
from rich.progress import Progress
from rich import print
from rich.table import Table

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

@dataclass
class Score:
    plain_text: Union[str, bytes]
    key: Union[str, bytes]
    file_type: str
    eng_fitness: float
    eng_similarity: float
    printable_percent:float
    score:float

    def __lt__(self, other:Score):
        return self.score < other.score


class KeyScorer:
    def __init__(self, cipher_text, decrypt_func:Callable):
        self.cipher_text = cipher_text
        self.decrypt_func = decrypt_func
        self.scores:List[Score] = list()

    def score(self, keys, key_scores, hook:Callable[[List[Score]]] = None):
        assert len(keys) == len(key_scores)

        with Pool() as p:
            with Progress() as progress:
                task_id = progress.add_task("Decrypting and Scoring...", total=len(keys))
                for result in p.imap(fitness_multiproc, ((key, score, self.cipher_text, self.decrypt_func) for key, score in zip(keys, key_scores))):
                    self.scores.append(result)
                    progress.advance(task_id)

        # Special Logic that might make more sense for a particular cipher
        if hook is None:
            hook = KeyScorer._default_hook
        self.scores = hook(self.scores)

        self.scores = sorted(self.scores, reverse=True)

    def print(self, top_percent:int=25):
        assert top_percent > 0 and top_percent <= 100
        assert len(self.scores) > 0

        table = Table(title="Plaintexts")
        table.add_column("Plain Text")
        table.add_column("Key")
        table.add_column("File Type")
        table.add_column("English Fitness Score")
        table.add_column("English Similarity Score")
        table.add_column("Printable Character %")
        table.add_column("Overall Score")

        # top_proportion = (100 - top_percent) / 100
        top_percent = top_percent / 100
        for i, score in enumerate(self.scores):
            if i > len(self.scores) // top_percent:
                break

            table.add_row(
                repr(score.plain_text[:24])[2:-1],
                repr(score.key)[2:-1],
                score.file_type[:16],
                "{:.2f}".format(score.eng_fitness * 1000),
                "{:.2f}".format(score.eng_similarity),
                "{:.2f}%".format(score.printable_percent*100),
                "{:.2f}".format(score.score)
            )
        print(table)


    @staticmethod
    def _default_hook(scores:List[Score]):
        # Write a custom hook and pass it into scores to do extra modification
        # to the scored key/plaintext combos that make sense for the specific cipher
        return scores


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

    return Score(plain_txt, key, file_type, eng_fitness, eng_similiarity, printable_percent, score)

def fitness_multiproc(args):
    key, key_score, cipher_text, decrypt_func = args
    return fitness(key, key_score, cipher_text, decrypt_func)

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

