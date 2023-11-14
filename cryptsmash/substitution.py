from typing import Dict, Union
import string
import random
import math

from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress

import asciichartpy as acp

from cryptsmash.plaintext import fitness

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

def smash(ctxt:Union[str, bytes], alphabet=string.ascii_lowercase, crib:Dict[str,str]=None, verbose=False):
    if crib == None:
        crib = dict()

    # Set of symbols that map to unknown values
    unknowns = set(alphabet) - set(crib.keys())
    unknown_targets = set(alphabet) - set(crib.values())

    candidate_keys = dict()
    for k, v in zip(unknowns, random.sample(unknown_targets, k=len(unknown_targets))):
        candidate_keys[k] = v

    key = dict(**candidate_keys, **crib)
    best_score = fitness(key, 1, ctxt, decrypt)
    exp_scale = 2 - round(math.log10(best_score.score)) 

    suboptimal_count = 0
    count = 0
    temp = 1
    score_history = [best_score.score]
    max_runs = 1000

    # prev_k = key
    with ProgressTable() as bar:
        bar.exp_scale = exp_scale
        task = bar.add_task("Simulated Annealing", total=max_runs, scores=score_history, best=best_score)
        while suboptimal_count < max_runs:
            k1, k2 = random.sample(unknowns, k=2)
            tmp = candidate_keys[k1]
            candidate_keys[k1] = candidate_keys[k2]
            candidate_keys[k2] = tmp

            key = dict(**candidate_keys, **crib)
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

            if score > best_score or random.random() < metro:            
                suboptimal_count = 0
                if verbose:
                    if score_history[-1] != score.score:
                        score_history.append(score.score)
                        score_history = score_history[-100:]
                        bar.update(task, scores=score_history, best=best_score)
                        bar.reset(task, total=max_runs)
                        
            else:
                suboptimal_count += 1
                bar.update(task, advance=1, scores=score_history, best=best_score)

            
            count += 1


    return [key]