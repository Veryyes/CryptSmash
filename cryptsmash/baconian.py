import string

######################################################################
# Bacon's Cipher is more of a 5bit encoding scheme than a cipher imo #
######################################################################

standard_bacon = {
        'a': "aaaaa",
        'b': "aaaab",
        'c': "aaaba",
        'd': "aaabb",
        'e': "aabaa",
        'f': "aabab",
        'g': "aabba",
        'h': "aabbb",
        'i': "abaaa",
        'j': "abaaa",
        'k': "abaab",
        'l': "ababa",
        'm': "ababb",
        'n': "abbaa",
        'o': "abbab",
        'p': "abbba",
        'q': "abbbb",
        'r': "baaaa",
        's': "baaab",
        't': "baaba",
        'u': "baabb",
        'v': "baabb",
        'w': "babaa",
        'x': "babab",
        'y': "babba",
        'z': "babbb",
    }

standard_bacon_rev = dict()
for k,v in standard_bacon.items():
     standard_bacon_rev[v] = k   

def encrypt(ptxt:str, symb1='A', symb2='B', standard=True):
    ctxt = list()
    if standard:
        for p in ptxt:
            p = p.lower()
            ctxt.append(standard_bacon[p])
        ctxt = ''.join(ctxt)
        ctxt = ctxt.replace('a', symb1)
        ctxt = ctxt.replace('b', symb2)
    else:
        for p in ptxt:
            p = p.lower()
            ctxt.append(bin(string.ascii_lowercase.index(p))[2:])
        ctxt = ''.join(ctxt)
        ctxt = ctxt.replace('0', symb1)
        ctxt = ctxt.replace('1', symb2)
    
    return ctxt

def decrypt(ctxt:str, symb1='A', symb2='B', standard=True):
    ptxt = list()
    if standard:
        ctxt = ctxt.replace(symb1, 'a')
        ctxt = ctxt.replace(symb2, 'b')

        for i in range(0, len(ctxt), 5):
            block = ctxt[i:i+5]
            ptxt.append(standard_bacon_rev[block]) 
    else:
        ctxt = ctxt.replace(symb1, '0')
        ctxt = ctxt.replace(symb2, '1')
        
        for i in range(0, len(ctxt), 5):
            block = ctxt[i:i+5]
            ptxt.append(chr(int(block,2) + ord('a')))

    return ''.join(ptxt)
