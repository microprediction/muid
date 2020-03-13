from muid.corpus import search
from muid.crypto import mhash

def animal(key):
    code = mhash(key)
    return search(code)

def validate(key):
   return animal(key) is not None



