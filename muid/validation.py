from muid.corpus import search
from muid.crypto import bhash

def animal(key):
    code = bhash(key)
    return search(code)

def validate(key):
   return animal(key) is not None



