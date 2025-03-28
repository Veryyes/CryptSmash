import string

from cryptsmash.plaintext import English, Language
from cryptsmash.utils import alphabet_dist, polyalpha_keylen


def encrypt(ptxt, key, alphabet=string.ascii_lowercase):
    alphabet = list(alphabet)
    ctxt = list()
    
    for i, p in enumerate(ptxt):
        if p not in alphabet:
            ctxt.append(p)
        else:
            ordinal = alphabet.index(p)
            ord_key = alphabet.index(key[i%len(key)])
            ctxt.append(alphabet[(ordinal + ord_key) % len(alphabet)])

    return "".join(ctxt)

def decrypt(ctxt, key, alphabet=string.ascii_lowercase):
    ptxt = list()
    ctxt = [c for c in ctxt if c in alphabet]
    alphabet = list(alphabet)

    for i, c in enumerate(ctxt):
        ordinal = alphabet.index(c)
        ord_key = alphabet.index(key[i%len(key)])
        ptxt.append(alphabet[(ordinal-ord_key) % len(alphabet)])

    return "".join(ptxt)

def smash(ctxt, alphabet=string.ascii_lowercase, presumed_lang:Language=English):
    ctxt = [c for c in ctxt if c in alphabet]
    
    threshold = 0
    
    alpha_dist = alphabet_dist(alphabet, presumed_lang)
    for dist in alpha_dist.values():
        threshold += dist * dist
        
    # Sum of squares 
    threshold = sum(threshold)

    key_length = polyalpha_keylen(ctxt, alphabet=alphabet)
    # print(key_length)
    keys = list()

    for key_len in range(2, key_length+1):
        freqs = list()
        for _ in range(key_len):
            freq = dict()
            for char in alphabet:
                freq[char] = 0
            freqs.append(freq)

        # Count letter freq by modulo of index
        for i, c in enumerate(ctxt):
            freqs[i % key_len][c] += 1
            
        # Convert count to probs
        for freq in freqs:
            ttl_char_count = sum(list(freq.values()))
            for char in freq.keys():
                freq[char] = freq[char] / ttl_char_count
        
        key = list()
        for i in range(key_len):
            best_cost = 10e10
            best = None

            # try each
            for shift in range(len(alphabet)):
                total = 0
                for char in alpha_dist.keys():
                    idx = alphabet.index(char)
                    total += alpha_dist[char] * freqs[i][alphabet[(idx + shift) % len(alphabet)]]

                cost = abs(total - threshold)
                if cost < best_cost:
                    best_cost = cost
                    best = alphabet[shift]

            key.append(best)

        key = ''.join(key)
        keys.append(key)
    
    return keys