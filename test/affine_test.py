from cryptsmash.affine import encrypt, decrypt

p = "didyouknowbungeegumhasboththepropertiesofrubberandgum"

def test_affine_enc():
    assert encrypt(p, (5, 9)) == "yxyzbfhwbpofwnddnfrsjvobasasdgqbgdqaxdvbiqfoodqjwynfr"

def test_affine_corr():
    assert decrypt(encrypt(p, (7, 13)), (7, 13)) == p