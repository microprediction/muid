import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent

py_version = sys.version_info
if py_version.major >= 3 and py_version.minor >= 6:     # Python version >= 3.6
    with open(HERE / "animals.json") as f:
        CORPUS = json.load(f)
else:                                                   # Python version < 3.6
    with open(str(HERE / "animals.json")) as f:
        CORPUS = json.load(f)

BCORPUS = dict( [ (k.encode('ascii'),v) for k,v in CORPUS.items() ])

def search(code=None):
    """ Return spirit animal given public identity """
    bcode = code if isinstance(code, bytes) else code.encode('ascii')
    for k in range(16,5,-1):
        code_k = bcode[:k]
        ks = BCORPUS.get(code_k)
        if ks:
            k1,k2 = ks
            return pretty(code=code_k, k1=k1, k2=k2)

def pretty(code, k1, k2):
    """ Just the animal """
    w1 = code[:k1]
    w2 = code[k1:k1 + k2]
    a1 = w1.decode('ascii')
    a2 = w2.decode('ascii')
    r1 = to_readable_hex(a1)
    r2 = to_readable_hex(a2)
    return r1[0].upper() + r1[1:] + ' ' + r2[0].upper() + r2[1:]

def to_readable_hex(word):
    """ Make hex a little more readable """
    return word.replace('0', 'o').replace('1', 'l').replace('2', 'z').replace('3', 'm').replace('4', 'y').replace(
        '5', 's').replace('6', 'h').replace('7', 't').replace('8', 'x').replace('9', 'g')

def from_readable_hex(word):
    """ Convert back to valid hex characters """
    return word.replace('o', '0').replace('l', '1').replace('z', '2').replace('m', '3').replace('y', '4').replace(
        's', '5').replace('h', '6').replace('t', '7').replace('x', '8').replace('9', 'g')



