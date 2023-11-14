import random
from multiprocessing import Pool

from cryptsmash.utils import ProcessSafePriorityQueue

q = ProcessSafePriorityQueue()

def _put(x):
    q.put(x)

def _get(x):
    return q.get()

def test_put():
    q.clear()
    with Pool(4) as p:
        p.map(_put, [(random.random(), None) for _ in range(500)])

    # single proc, reach into internals check
    for i in range(len(q) - 1):
        assert q.queue[i][0] < q.queue[i+1][0], f"Queue out of order: {q.queue}"

    # tests get
    prior_scores = list()
    last_score, _ = q.get()
    prior_scores.append(last_score)
    while len(q) > 0:
        score, _ = q.get()
        assert score >= max(prior_scores), f"Queue out of order: {q.queue}"
            

def test_get():
    q.clear()
    with Pool(4) as p:
        p.map(_put, [(random.random(), None) for _ in range(500)])
        
        ret = p.map(_get, [None]*500)

    for i in range(len(ret) - 1):
        assert ret[i][0] < ret[i+1][0], f"Queue out of order: {q.queue}"