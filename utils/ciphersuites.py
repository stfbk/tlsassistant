from utils.loader import load_configuration


def get_1_3_ciphers():
    ciphers = {}
    dictionary = load_configuration("ciphersuites", "configs/compliance/")
    for cipher in dictionary:
        val = dictionary[cipher]["OpenSSL"]
        if cipher.startswith("0x13,") and val:
            key = dictionary[cipher]["IANA"]
            ciphers[key] = val
    return ciphers

def filter_1_3_ciphers(ciphers):
    ciphers_1_3 = get_1_3_ciphers()
    return {cipher: ciphers.pop(cipher) for cipher in ciphers_1_3 if cipher in ciphers}