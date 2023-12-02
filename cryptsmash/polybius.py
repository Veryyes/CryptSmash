from typing import Dict

from cryptsmash.substitution import encrypt as sub_encrypt
from cryptsmash.substitution import decrypt as sub_decrypt

def _convert_key(key:Dict[Dict], inv=False):
    sub_key = dict()

    if not inv:
        for i in key.keys():
            for j in key[i].keys():
                sub_key[key[i][j]] = str(i)+str(j)
    else:
        for i in key.keys():
            for j in key[i].keys():
                sub_key[str(i)+str(j)] = key[i][j]
        
def encrypt(ptxt, key:Dict[Dict]):
    key = _convert_key(key)
    return sub_encrypt(ptxt, key)
    
def decrypt(ctxt, key:Dict[Dict]):
    key = _convert_key(key, inv=True)
    
    # Since a substitution is just a mapping
    # just use sub_encrypt with the inverted key
    return sub_encrypt(ctxt, key)

    

