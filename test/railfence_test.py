from cryptsmash.railfence import encrypt, decrypt

p = "didyouknowbungeegumhasboththepropertiesofrubberandgum"

def test_rail_enc():
    assert encrypt(p, 5) == "dogtpfninweuohoeoraddkbembtrrsurgyuughshptebeuonaeibm"

def test_rail_corr():
    key = 7
    assert decrypt(encrypt(p, key), key) == p

    key = 8
    assert decrypt(encrypt(p, key), key) == p