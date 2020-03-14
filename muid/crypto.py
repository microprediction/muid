from hashlib import sha256

def bhash(key):
    """ Hash binary to binary """
    # Remark (1) Strings are in the ascii character set so ascii==utf-8 here
    # Remark (2) There is little to be gained by not encoding back to binary
    #            timeit.timeit(setup="from hashlib import sha256; h=sha256(b'dog').hexdigest()[:32].encode('ascii')",number=100000000)
    return sha256(key).hexdigest()[:32].encode('ascii')

def shash(s):
    """ Hash string to string """
    return sha256(s.encode('ascii')).hexdigest()[:32]