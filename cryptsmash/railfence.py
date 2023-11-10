import math

from cryptsmash.plaintext import fitness


def encrypt(ptxt:str, key:int):
    buckets = [list() for _ in range(key)]
    up = False
    mod = key-1
    for i, p in enumerate(ptxt):
        if up:
            buckets[mod - (i%mod)].append(p)
        else:
            buckets[i%mod].append(p)

        if i % mod == mod - 1:
            up = not up

    return "".join(["".join(b) for b in buckets])

def decrypt(ctxt:str, key:int):
    if key == 1 or key == len(ctxt):
        return ctxt

    mod = key - 1
    period = (key * 2) - 2
    leftover = (len(ctxt) % period) - 1

    lines = []

    peaks = math.ceil(len(ctxt) / (2 * key - 2))
    lines.append(list(ctxt[:peaks]))

    prev_len = peaks
    for i in range(0, key):
        line_len = 2 * peaks - 2
        if i < leftover:
            line_len += 1
        if leftover >= key and i > (leftover - key):
            line_len += 1

        lines.append(list(ctxt[prev_len:prev_len + line_len]))
        prev_len += line_len

    ptxt = []
    i = 0
    up = False

    while i < len(ctxt):
        if up:
            idx = mod - (i%mod)
        else:
            idx = i%mod
        
        if len(lines[idx]) != 0:
            ptxt.append(lines[idx].pop(0))

        if i % mod == mod - 1:
            up = not up

        i += 1

    return "".join(ptxt)

def smash(ctxt:str):
    return list(range(3, len(ctxt)))

def railfence_fitness(key:str, key_score:str, ctxt:str):
    return fitness(key, key_score, ctxt, decrypt)