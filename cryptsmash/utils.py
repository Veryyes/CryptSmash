import multiprocessing
from typing import Callable, Iterable, Tuple, List, Any, IO
from concurrent.futures import ProcessPoolExecutor
import pkgutil
import os
import io

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

def read_blks(f:IO, block_size):
    data = f.read(block_size)
    while data:
        yield data
        data = f.read(block_size)
        
def byte_prob(f:IO):
    data = f.read()
    np_data = np.frombuffer(data, dtype=np.uint8)
    return np.bincount(np_data, minlength=256) / len(np_data)
    

def rich_map(func:Callable, args:Iterable[Tuple], total=None, num_cores=None, job_title=None) -> List[Any]:
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
                        total=len(futures)
                    )
                    for task_id, update_data in _progress.items():
                        latest = update_data['progress']
                        total = update_data['total']
                        progress_bar.update(
                            task_id,
                            completed=latest,
                            total=total,
                            visible=latest < total
                        )

                progress_bar.update(
                        overall_progress_task,
                        completed=len(futures),
                        total=len(futures)
                    )
                return [f.result() for f in futures]