from cryptsmash.substitution import encrypt, decrypt

p = "didyouknowbungeegumhasboththepropertiesofrubberandgum"

def test_sub_enc():
    key = dict(zip("abcdefghijklmnopqrstuvwxyz", "twnjszeudkhaomxlryfcgqbipv"))
    assert encrypt(p, key) == "jdjpxghmxbwgmessegoutfwxcucuslyxlsycdsfxzygwwsytmjego"

def test_sub_corr():
    key = dict(zip("abcdefghijklmnopqrstuvwxyz", "twnjszeudkhaomxlryfcgqbipv"))
    assert decrypt(encrypt(p, key), key) == p