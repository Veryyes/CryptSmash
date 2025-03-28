from __future__ import annotations

import multiprocessing
from typing import Callable, Iterable, Tuple, Dict, List, Set, Any, IO, Hashable, Union
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import pkgutil
import os
import io
import math
import string

import numpy as np
from rich import progress


def data_dir():
    return os.path.join(os.path.dirname(pkgutil.get_loader('cryptsmash').path), 'data')

def f_size(f:IO):
    cur = f.tell()
    f.seek(0, io.SEEK_END)
    size = f.tell()
    f.seek(cur)

    return size
       
def byte_prob(data:bytes):
    np_data = np.frombuffer(data, dtype=np.uint8)
    return np.bincount(np_data) / len(np_data)

def entropy(data:bytes):
    prob = byte_prob(data)
    prob = prob[prob != 0]
    return (-np.nansum(prob * np.log2(prob))) / 8

def ngram_prob(data:bytes, n:int=2):
    counts = ngram_count(data, n)
    
    for k, v in counts.items():
        counts[k] = v / len(data)

    return counts

def ngram_count(data:bytes, n:int=2):
    counts = defaultdict(lambda: 0)
    for i in range(len(data) - n):
        counts[data[i:i+n]] += 1

    return counts

def alphabet_dist(alphabet:List, lang:'Language', encoding='utf8') -> Dict[Union[str, bytes]: float]:
    alpha_dist = dict()

    is_bytes = isinstance(alphabet[0], bytes)

    for a in alphabet:
        if not is_bytes:
            _a = bytes(_a, encoding=encoding)
        else:
            _a = a

        alpha_dist[a] = lang.byte_distrib[_a]

    return alpha_dist

def frequency_table(
    data:Hashable
) -> Dict[Hashable, int]:

    freq = defaultdict(lambda: 0)

    for d in data:
        # TODO d into bytes
        freq[d] += 1

    return freq

def has_printable(data:bytes):
    printables = bytes(string.printable, 'ascii')
    return all(c in printables for c in data)

def has_non_printables(data:bytes):
    printables = bytes(string.printable, 'ascii')
    return any(c not in printables for c in data)

#http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/
def inv_chi_squared(
    counts:Dict[bytes, int], 
    distrib:Dict[bytes, float], 
    length:int, 
    alphabet:Set[bytes]=set([int.to_bytes(x, length=1, byteorder='little') for x in range(256)])
) -> float:
    '''
    The Chi-squared Statistic is a measure of how similar two categorical probability distributions are. 
    If the two distributions are identical, the chi-squared statistic is 0, 
    if the distributions are very different, some higher number will result

    :param counts: frequency table (counts) of the data
    :param distrib: distribution of symbols to compare against (sum to 1)
    :param length: length of cipher text
    '''
    assert length > 0

    max_factor = max(distrib.values()) ** 2
    
    assert max_factor > 0, "Everything in the distribution is 0!"

    running_sum = 1.0
    for letter in alphabet:
        if distrib.get(letter, 0) == 0:
            running_sum += (math.pow(counts[letter] - (max_factor*length), 2) / (max_factor*length))
        else:
            running_sum += (math.pow(counts[letter] - (distrib[letter]*length), 2) / (distrib[letter]*length))

    return 1 / running_sum

# http://practicalcryptography.com/cryptanalysis/text-characterisation/index-coincidence/
@staticmethod
def index_of_coincidence(
    data:bytes
) -> float:
    '''
    measure of how similar a frequency distribution is to the uniform distribution
    '''
    denominiator = len(data) * (len(data) - 1)
    numerator = 0
    frequency = frequency_table(data)
    for count in frequency.values():
        numerator += (count * (count - 1))
    
    return numerator / denominiator


@staticmethod
def polyalpha_keylen(ctxt, max_key_len=32, alphabet=string.ascii_lowercase):
    ioc_periods = list()

    for i in range(1, max_key_len):
        seqs = [list() for _ in range(i)]
        count = 0
        for char in ctxt:
            seqs[count%i].append(char)
            count += 1

        ioc_values = list()

        for seq in seqs:
            if len(seq) < 2:
                ioc_values.append(0)
            else:
                ioc_values.append(index_of_coincidence(''.join(seq), alphabet=alphabet))

        ave_ioc = np.average(np.array(ioc_values))
        ioc_periods.append(ave_ioc)

    return np.argmax(ioc_periods) + 1

def rich_map(func:Callable, args:Iterable[Tuple], total=None, num_cores=None, job_title=None, disabled=False) -> List[Any]:
    '''
    Map a function against several sets of arguments while also printing rich progress bars. Similar to Pool.map
    Functions passed in may use the optional keyword arguments: progress and task_id to update the worker's current progress.
    
    <code>progress[task_id] = {"progress": 69, "total": 100}</code>
    :param func: The function to map
    :param args: An Iterable of Tuples where each tuple is the set of arguments for each function call
    :param total: the number of elements in args. This is used when `args` does not have a __len__ function (e.g. a generator).
    :param num_cores: Number of cores/workers to map with. Set to None for all the cpus on the machine
    :returns: List of each return value
    '''
    with progress.Progress(
        "[progress.description]{task.description}",
        progress.BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        progress.TimeRemainingColumn(),
        progress.TimeElapsedColumn(),
        refresh_per_second=1,
        disable=disabled
    ) as progress_bar:
        futures = []
        with multiprocessing.Manager() as manager:
            _progress = manager.dict()
            overall_progress_task = progress_bar.add_task(func.__name__ if job_title is None else job_title)

            with ProcessPoolExecutor(max_workers=num_cores) as executor:
                num_tasks = len(args) if total is None else total
                # TODO
                # This loop takes a really long time to do when len(args) is really big
                for i, arg in enumerate(args):
                    assert isinstance(arg, tuple)
                    task_id = progress_bar.add_task(f"({i+1}/{num_tasks})", visible=False)
                    futures.append(executor.submit(func, *arg, progress=_progress, task_id=task_id))
                while (n_finished := sum([f.done() for f in futures])) < len(futures):
                    progress_bar.update(
                        overall_progress_task,
                        completed=n_finished,
                        total=len(futures),
                        visibl=not disabled
                    )

                    for task_id, update_data in _progress.items():
                        latest = update_data['progress']
                        total = update_data['total']
                        progress_bar.update(
                            task_id,
                            completed=latest,
                            total=total,
                            visible=latest < total and (not disabled)
                        )

                # Overall Progress Completed
                progress_bar.update(
                    overall_progress_task,
                    completed=len(futures),
                    total=len(futures),
                    visible=not disabled
                )
                return [f.result() for f in futures]

class ProcessSafePriorityQueue:
    def __init__(self):
        self.queue = multiprocessing.Manager().list()
        self.lock = multiprocessing.Lock()

    def put(self, x):
        priority, _ = x
        with self.lock:
            if len(self.queue) == 0:
                self.queue.append(x)
            else:
                for i, e in enumerate(self.queue):
                    queued_priority, _ = e
                    if priority < queued_priority:
                        self.queue.insert(i, x)
                        break
                else:
                    self.queue.append(x)
                

    def get(self):
        with self.lock:
            if len(self.queue) > 0:
                return self.queue.pop(0)
            else:
                return None

    def empty(self):
        return len(self) == 0

    def clear(self):
        with self.lock:
            del self.queue[:]

    def __len__(self):
        with self.lock:
            return len(self.queue)