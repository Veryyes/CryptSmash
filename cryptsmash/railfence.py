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
    # This almost works...
    if key == 1 or key == len(ctxt):
        return ctxt

    modulo = key - 1
    period = (key*2) - 2 
    leftover = (len(ctxt) % period) - 1

    lines = []

    peaks = math.ceil(len(ctxt) / (2*key-2))
    lines.append(list(ctxt[:peaks]))

    prev_len = peaks
    for i in range(0, key):
        line_len = peaks*2 - 2
        if i < leftover:
            line_len += 1
        if leftover >= key and i > (leftover - key):
                line_len += 1

        lines.append(list(ctxt[prev_len:prev_len + line_len]))
        prev_len += line_len

    plain = []
    i = 0
    up = False
    while i < len(ctxt):
        if up:
            idx = modulo - (i%modulo)    
        else:
            idx = i%modulo

        if len(lines[idx]) != 0:
            plain.append(lines[idx].pop(0))

        if i % modulo == modulo-1:
            up = not up

        i += 1

    return "".join(plain)

# Stolen from https://www.geeksforgeeks.org/rail-fence-cipher-encryption-decryption/
# Shit doesnt even work....
# def decrypt(ctxt:str, key:int):
#     rail = [['\n' for i in range(len(ctxt))] for j in range(key)]
     
#     # to find the direction
#     dir_down = None
#     row, col = 0, 0
     
#     # mark the places with '*'
#     for i in range(len(ctxt)):
#         if row == 0:
#             dir_down = True
#         if row == key - 1:
#             dir_down = False
         
#         # place the marker
#         rail[row][col] = '*'
#         col += 1
         
#         # find the next row
#         # using direction flag
#         if dir_down:
#             row += 1
#         else:
#             row -= 1
             
#     # now we can construct the
#     # fill the rail matrix
#     index = 0
#     for i in range(key):
#         for j in range(len(ctxt)):
#             if ((rail[i][j] == '*') and
#             (index < len(ctxt))):
#                 rail[i][j] = ctxt[index]
#                 index += 1
         
#     # now read the matrix in
#     # zig-zag manner to construct
#     # the resultant text
#     result = []
#     row, col = 0, 0
#     for i in range(len(ctxt)):
         
#         # check the direction of flow
#         if row == 0:
#             dir_down = True
#         if row == key-1:
#             dir_down = False
             
#         # place the marker
#         if (rail[row][col] != '*'):
#             result.append(rail[row][col])
#             col += 1
             
#         # find the next row using
#         # direction flag
#         if dir_down:
#             row += 1
#         else:
#             row -= 1
#     return("".join(result))
    

def smash(ctxt:str):
    return list(range(3, len(ctxt)))

def railfence_fitness(key:str, key_score:str, ctxt:str):
    return fitness(key, key_score, ctxt, decrypt)