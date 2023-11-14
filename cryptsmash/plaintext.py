from __future__ import annotations
from typing import get_type_hints, Type, Tuple, Callable, Union, List, Dict, Hashable, Any
import os
import json
import csv
from math import log10
from multiprocessing import Pool
from dataclasses import dataclass

import magic
from rich.progress import Progress
from rich import print
from rich.table import Table

from cryptsmash.utils import data_dir, inv_chi_squared, frequency_table
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
    key: Hashable
    file_type: str
    eng_fitness: float
    eng_similarity: float
    eng_word_score: float
    printable_percent:float
    score:float

    def __repr__(self):
        return f"<Score ftype: {self.file_type}, eng_fit: {self.eng_fitness:.3f}, eng_sim: {self.eng_similarity:.3f}, eng_word:{self.eng_word_score:.3f}, printable: {self.printable_percent*100:.1f}, score: {self.score:.4f}>"

    def __hash__(self):
        return hash(self.key)

    def __lt__(self, other:Score):
        return self.score < other.score

    def __gt__(self, other:Score):
        return self.score > other.score

class KeyScorer:
    def __init__(self, cipher_text, decrypt_func:Callable):
        self.cipher_text = cipher_text
        self.decrypt_func = decrypt_func
        self.scores:List[Score] = list()

        # Keep a map of the best Score for each sub score (and the overall one)
        self.bests = dict()
        for var_name, var_type in get_type_hints(Score).items():
            if var_type == float or var_type == int:
                self.bests[var_name] = None
        

    def add(self, s:Score):
        self.scores.append(s)

        # Keep Track of the best score for each subscore (and the overall one)
        for var_name in self.bests.keys():
            if self.bests[var_name] is None:
                self.bests[var_name] = s

            elif getattr(s, var_name) > getattr(self.bests[var_name], var_name):
                self.bests[var_name] = s

    def score(self, keys, key_scores=None, hook:Callable[[List[Score]]] = None):
        if key_scores is None:
            key_scores = [1] * len(keys)

        assert len(keys) == len(key_scores)

        with Pool() as p:
            with Progress() as progress:
                task_id = progress.add_task("Decrypting and Scoring...", total=len(keys))
                for result in p.imap(fitness_multiproc, ((key, score, self.cipher_text, self.decrypt_func) for key, score in zip(keys, key_scores))):
                    self.add(result)
                    progress.advance(task_id)

        # Special Logic that might make more sense for a particular cipher
        if hook is None:
            hook = KeyScorer._default_hook
        self.scores = hook(self.scores)

        self.scores = sorted(self.scores, reverse=True)

    def print(self, top_percent:int=25):
        if not (top_percent >= 0 and top_percent <= 100):
            raise ValueError("Percentage must be between [0, 100]")

        assert len(self.scores) > 0

        table = Table(title=f"Plaintexts (Top {top_percent} %)")
        table.add_column("Plain Text")
        table.add_column("Key")
        table.add_column("File Type")
        table.add_column("Eng Fitness Score")
        table.add_column("Eng Similarity Score")
        table.add_column("Eng KeyWord Score")
        table.add_column("Printable Character %")
        table.add_column("Overall Score")
        
        top_percent = top_percent / 100 
        for i, score in enumerate(self.scores):
            if i > len(self.scores) * top_percent:
                break

            if isinstance(score.key, bytes):
                key = repr(score.key)[2:-1]
            else:
                key = str(score.key)

            if isinstance(score.plain_text, bytes):
                ptxt = repr(score.plain_text[:24])[2:-1]
            else:
                ptxt = str(score.plain_text)

            row = (
                ptxt,
                key,
                score.file_type[:16],
                "{:.2f}".format(score.eng_fitness * 1000),
                "{:.2f}".format(score.eng_similarity),
                "{:.2f}".format(score.eng_word_score),
                "{:.2f}%".format(score.printable_percent*100),
                "{:.4f}".format(score.score)
            )

            for best_subscore in self.bests.values():
                if score == best_subscore:
                    table.add_row(*row, style='green')
                    break
            else:
                table.add_row(*row)

        print(table)


    @staticmethod
    def _default_hook(scores:List[Score]):
        # Write a custom hook and pass it into scores to do extra modification
        # to the scored key/plaintext combos that make sense for the specific cipher
        return scores


def fitness(key:Any, key_score:float, cipher_text:Union[str, bytes], decrypt:Callable):
    plain_txt = decrypt(cipher_text, key)

    if key_score == 0:
        key_score = .0001

    score = key_score
    
    known_file, file_type = is_known_file(plain_txt)
    if known_file:
        score *= .99
    else:
        score *= .005
    
    
    eng_fitness = quadgram_fitness(plain_txt.upper(), English)
    eng_similiarity = inv_chi_squared(frequency_table(plain_txt), English.byte_distro, len(plain_txt))    
    eng_word_score = keyword_score(plain_txt, English.word_count)    

    printable_percent = printable_percentage(plain_txt)
    
    score *= eng_fitness * eng_similiarity * printable_percent * eng_word_score
    score = score**(1/6)

    return Score(plain_txt, key, file_type, eng_fitness, eng_similiarity, eng_word_score, printable_percent, score)

def fitness_multiproc(args):
    key, key_score, cipher_text, decrypt_func = args
    return fitness(key, key_score, cipher_text, decrypt_func)

def printable_percentage(data:bytes) -> float:
    '''
    Returns the percentage of bytes that are printable
    '''
    if isinstance(data, str):
        return 1

    count = 0
    for b in data:
        if b >= 32 and b <= 126:
            count += 1

    return count / len(data)

def keyword_score(data, score_table:Dict):
    score = 0
    data = data.lower()
    for word, prob in score_table.items():
        if isinstance(data, bytes):
            word = bytes(word, 'ascii')

        if word in data:
            score += prob
    return score

def quadgram_fitness(data:bytes, lang:Type[Language]) -> float:
    score = 0
    lowest = log10(1 + (0.01/lang.quadgram_total))
    for i in range(len(data) - 3):
        score += lang.quadgrams.get(data[i:i+4], lowest)
    return score / (len(data)/4)

def is_known_file(data:bytes) -> Tuple[bool, str]:
    _type = magic.from_buffer(data[:2048]).strip()
    return _type != "data", _type

class Language:
    ENCODING = "UTF8"
    byte_distro:Dict[int, float]
    quadgrams:Dict[bytes, int]
    quadgram_total:int = 1
    word_count:Dict[str, float]

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

    total = 0
    word_count = dict()
    with open(os.path.join(data_dir(), "english_word_count.tsv"), 'r') as f:
        tsv = csv.reader(f, delimiter='\t')
        for row in tsv:
            word_count[row[0]] = int(row[1])
            total += int(row[1])

    for word in word_count.keys():
        word_count[word] = word_count[word] / total
