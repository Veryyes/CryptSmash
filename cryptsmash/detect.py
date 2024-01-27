from cryptsmash.utils import inv_chi_squared, frequency_table, index_of_coincidence
from cryptsmash.plaintext import English

#############################################
# Attempt Decryption with all Keys and Rank #
#############################################
# All ASCII -> Good (But not Bad thing if it isnt)
# Python Magic detects a non-data file -> Good
# Language Score

# def detect_decryption(decrypted_data:bytes, key):
    # known_file, file_type = is_known_file(decrypted_data)
    # if known_file:
    #     return True
# def decrypt_score(decrypted_data:bytes, key):
#     score = 1

#     # known_file, file_type = is_known_file(decrypted_data)
#     # if known_file:
#     #     score *= 
    
#     eng_fitness = quadgram_fitness(decrypted_data, English)
#     eng_similiarity = chi_squared(frequency_table(decrypted_data))
#     printable_percentage(decrypted_data)

LARGE_CORPUS = 75

def identify(ctxt:bytes):
    freq_table = frequency_table(ctxt)
    chi_sq = inv_chi_squared(freq_table, English.byte_distro, len(ctxt))

    non_zero_keys = {k:freq_table[k] for k in freq_table.keys() if freq_table[k] > 0}

    # Only Two Symbols Exist?
    if len(non_zero_keys.keys()) == 2:
        return "Baconian"

    if len(non_zero_keys) == 5 or len(non_zero_keys) == 6:
        return "Polybus"

    # playfair, foursquare, bifid etc..
    if len(non_zero_keys) == 25 and len(ctxt) > LARGE_CORPUS:
        return "Square Cipher"

    if chi_sq < 120:
        return "Transposition"

    ioc = index_of_coincidence(ctxt)
    if ioc > .0525:
        return "Monoalphabetic"

    return "Polyalphabetic"