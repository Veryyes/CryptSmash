import multiprocessing
from typing import Callable, Iterable, Tuple, List, Any, IO
from concurrent.futures import ProcessPoolExecutor

from rich import progress

def read_blks(f:IO, block_size):
    data = f.read(block_size)
    while data:
        yield data
        data = f.read(block_size)

import IPython
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
    # IPython.embed()
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
                    # print(f"\r{i}")
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

# import time
# import random
# def lrs(data:bytes, progress=None, task_id=None):
#     data_size=len(data)

#     suffix = list()
#     for i in range(data_size):
#         suffix.append(data[data_size-i-1:data_size])

#         # Progress Bar
#         if progress is not None:
#             progress[task_id] = {"progress": i, "total": data_size*2}

#     suffix = sorted(suffix)
    
#     lrs=""
#     length=0
#     for i in range(data_size-1):
#         length = lcp(suffix[i], suffix[i+1], len(lrs))
#         if length > len(lrs):
#             lrs = suffix[i][0:length]

#         # Progress Bar
#         if progress is not None:
#             progress[task_id] = {"progress": data_size+i, "total": data_size*2}
    
#     return lrs

# def lcp(s1,s2,current_len):
#     # I think this stands for longest common prefix?

#     if(len(s1)<len(s2)):
#         limit=len(s1)
#     else:
#         limit=len(s2)

    
#     if(s1[0:limit]==s2[0:limit]): # if substring are the same at limit, return limit
#         return limit
    
#     if(limit < current_len):      # if the limit is less than the length of current duplicated substring, we don't need to 
#         return 0                  # compare.
#     else:
#         n = current_len
#         while(s1[0:n+1]==s2[0:n+1] and n<=limit):
#             n+=1
        
#         if(n>current_len):
#             return n
#         else:
#             return 0  
# d = '''The dog (Canis familiaris[4][5] or Canis lupus familiaris[5]) is a domesticated descendant of the wolf. Also called the domestic dog, it is derived from extinct Pleistocene wolves,[6][7] and the modern wolf is the dog's nearest living relative.[8] Dogs were the first species to be domesticated[9][8] by hunter-gatherers over 15,000 years ago[7] before the development of agriculture.[1] Due to their long association with humans, dogs have expanded to a large number of domestic individuals[10] and gained the ability to thrive on a starch-rich diet that would be inadequate for other canids.[11]

# The dog has been selectively bred over millennia for various behaviors, sensory capabilities, and physical attributes.[12] Dog breeds vary widely in shape, size, and color. They perform many roles for humans, such as hunting, herding, pulling loads, protection, assisting police and the military, companionship, therapy, and aiding disabled people. Over the millennia, dogs became uniquely adapted to human behavior, and the human–canine bond has been a topic of frequent study.[13] This influence on human society has given them the sobriquet of "man's best friend".[14]'''

# d = bytes(d, "utf8")

# # print(lrs(d))
# rich_map(lrs, [(d,),(d,),(d,),(d,),(d,),(d,),(d,),(d,),(d,),(d,)], num_cores=1)