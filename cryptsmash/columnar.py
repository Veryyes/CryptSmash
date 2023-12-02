from typing import List
import string
import math
import random

import numpy as np

def encrypt(ptxt, key=None, row_len=None, order:List[int]=None, irregular=False, alphabet=string.ascii_lowercase):
    # (row_len & order) mutually exclusive (key)
    if (key is None and row_len is None and order is None) or (key is not None and row_len is not None and order is not None):
        raise ValueError("key parameter is mutually exclusive with row_len and order parameters")

    if key is not None:
        row_len = len(key)
        # TODO change ord(c) to the ordering
        order = np.argpartition([ord(c) for c in key], len(key) - 1)

    
    mat = list()
    row = list()
    for i, p in enumerate(ptxt):
        c = i%row_len       
        row.append(p)
        if c + 1 == row_len:
            mat.append(row)
            row = list()

    # print(mat)
    col_len = math.ceil(len(ptxt) / row_len)
    
    ptxt = list()
    
    for idx in order:
        for r in range(col_len):
            try:
                ptxt.append(mat[r][idx])
            except IndexError:
                if not irregular:
                    ptxt.append(random.sample(alphabet, k=1)[0])

    return "".join(ptxt)

# def decrypt(ctxt, key=None, row_len=None, order:List[int]=None, irregular=False, alphabet=string.ascii_lowercase):
#     # (row_len & order) mutually exclusive (key)
#     if (key is None and row_len is None and order is None) or (key is not None and row_len is not None and order is not None):
#         raise ValueError("key parameter is mutually exclusive with row_len and order parameters")

#     if key is not None:
#         row_len = len(key)
#         # TODO change ord(c) to the ordering
#         order = np.argpartition([ord(c) for c in key], len(key) - 1)
    
#     col_len = len(ctxt)/row_len

#     mat = list()
#     # if not irregular:
#     print(col_len, len(ctxt), row_len)
#     print(order)
#     print(ctxt)



# c = encrypt("wearediscoveredfleeatonce", key='zebras', irregular=True)
# print(c)
# decrypt(c, key='zebras')