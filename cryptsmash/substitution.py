from typing import Dict, Union
import string
import random
import math

from rich import print
from rich.console import Group
from rich.panel import Panel
from rich.progress import Progress

import asciichartpy as acp

from cryptsmash.plaintext import fitness, English, Language
from cryptsmash.utils import frequency_table

def encrypt(ptxt:Union[str, bytes], key:Dict[Union[str, bytes], Union[str, bytes]]):
    ctxt = list()
    for p in ptxt:
        ctxt.append(key[p])
    
    if isinstance(list(key.values())[0], str):
        return "".join(ctxt)

    return b"".join(ctxt)

def decrypt(ctxt:Union[str, bytes], key:Dict[Union[str, bytes], Union[str, bytes]]):
    rev_key = dict()
    for k,v in key.items():
        rev_key[v] = k

    ptxt = list()
    for c in ctxt:
        # Anything not in the alphabet, just keep and throw it into the ptxt
        if c not in rev_key:
            ptxt.append(c)
        else:
            ptxt.append(rev_key[c])

    if isinstance(list(rev_key.values())[0], str):
        return "".join(ptxt)

    return b"".join(ptxt)

def _randomized_key(alphabet, crib):
    unknowns = set(alphabet) - set(crib.keys())
    unknown_targets = set(alphabet) - set(crib.values())

    candidate_keys = dict()
    for k, v in zip(unknowns, random.sample(unknown_targets, k=len(unknown_targets))):
        candidate_keys[k] = v

    return dict(**candidate_keys, **crib)


class ProgressTable(Progress):
    def get_renderables(self):

        for task in self.tasks:
            scores = task.fields['scores']
            self.exp_scale

            yield Group(
                f"Best Score: {task.fields['best'].score*(10**self.exp_scale):.4f}",
                self.make_tasks_table(self.tasks),
                Panel(acp.plot([s*(10**self.exp_scale) for s in scores], cfg={'height':20}), expand=False, title="Scoring Progress")
            )

def smash(ctxt:Union[str, bytes], alphabet=string.ascii_lowercase, crib:Dict[str,str]=None, verbose=False, presumed_lang:Language=English):
    if crib == None:
        crib = dict()

    # Set of symbols that map to unknown values
    unknowns = set(alphabet) - set(crib.keys())
    unknown_targets = set(alphabet) - set(crib.values())
    candidate_keys = dict()

    num_unknown_states = math.factorial(len(unknowns))

    #######################################################################################################
    # If the cipher text is big enough we use the frequency of the presumed language to seed the algorith #
    #######################################################################################################
    if presumed_lang is None or len(ctxt) < len(alphabet)*2:
        # Randomize
        for k, v in zip(unknowns, random.sample(unknown_targets, k=len(unknown_targets))):
            candidate_keys[k] = v
    else:
        print(f'[green] Using {presumed_lang.__name__} frequency to seed search')
        f_table = frequency_table(ctxt)
        for u in unknowns:
            if u not in f_table:
                f_table[u] = 0
        f_table = {k: f_table[k] for k in alphabet if k not in crib.keys()}

        symbols = sorted([(sym,count) for sym, count in f_table.items()], key=lambda x:x[1])
        
        # Cast the alphabet and crib to bytes because presumed_lang.byte_distro has bytes
        tmp_crib = {}
        if type(alphabet[0]) == str:
            tmp_alphabet = bytes(alphabet, 'utf8')

            for k,v in list(crib.items()):
                tmp_crib[bytes(k, encoding='utf8')] = bytes(v, encoding='utf8')
        else:
            tmp_crib = crib
            tmp_alphabet = alphabet

        targets = list()
        for sym, prob in presumed_lang.byte_distro.items():
            if sym in tmp_alphabet and sym not in tmp_crib.values():
                # Cast back to string if cipher text is string type
                if type(ctxt[0]) == str:
                    sym = str(sym, 'utf8')

                targets.append((sym, prob))
        targets = sorted(targets, key=lambda x:x[1])

        assert len(symbols) == len(targets)

        for preimg, img in zip(symbols, targets):
            candidate_keys[preimg[0]] = img[0]

    key = candidate_keys | crib
    best_key = key.copy()
    best_score = fitness(key, 1, ctxt, decrypt)
    exp_scale = 2 - round(math.log10(best_score.score)) 

    suboptimal_count = 0
    count = 0
    temp = .01
    score_history = [best_score.score]
    max_runs = min(10000, num_unknown_states)

    with ProgressTable() as bar:
        bar.exp_scale = exp_scale
        task = bar.add_task("Simulated Annealing", total=max_runs, scores=score_history, best=best_score)
        while suboptimal_count < max_runs:
            
            k1, k2 = random.sample(unknowns, k=2)
            tmp = candidate_keys[k1]
            candidate_keys[k1] = candidate_keys[k2]
            candidate_keys[k2] = tmp

            # key = dict(**candidate_keys, **crib)
            key = candidate_keys | crib
            score = fitness(key, 1, ctxt, decrypt)

            diff = best_score.score - score.score
            # when diff is more negative it exponentially grows and we can get an overflow err
            # 1 is the max needed value
            if diff < 0:
                metro = 1
            else:
                metro = math.exp(-diff / (temp / (count+1)))
            
            if score > best_score:
                best_score = score
                best_key = key.copy()

            if score > best_score or random.random() < metro:            
                suboptimal_count = 0
                if verbose:
                    if score_history[-1] != score.score:
                        score_history.append(score.score)
                        score_history = score_history[-100:]
                        bar.update(task, scores=score_history, best=best_score)
                        bar.reset(task, total=max_runs)
                        
            else:
                # This was shittier option, swap back to the parent to regen a child
                tmp = candidate_keys[k1]
                candidate_keys[k1] = candidate_keys[k2]
                candidate_keys[k2] = tmp

                suboptimal_count += 1
                bar.update(task, advance=1, scores=score_history, best=best_score)

            
            count += 1
    print(f"Approx {100 * (count / num_unknown_states)}% of search space covered")

    return [best_key]