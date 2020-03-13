from muid.corpus import to_readable_hex, BCORPUS
from muid.crypto import mhash

def to_memorable(key=None, code=None):
    """ Return spirit animal given either private or public identity """
    code = code or mhash(key)
    ks = BCORPUS.get(code)
    if ks:
        k1,k2 = ks
        return to_pretty(code=code, k1=k1, k2=k2)

def to_pretty(code, k1, k2):
    """ Just the animal """
    w1 = code[:k1]
    w2 = code[k1:k1 + k2]
    a1 = w1.decode('ascii')
    a2 = w2.decode('ascii')
    r1 = to_readable_hex(a1)
    r2 = to_readable_hex(a2)
    return r1[0].upper() + r1[1:] + ' ' + r2[0].upper() + r2[1:]

def is_muid(key):
    return to_memorable(key=key) is not None



