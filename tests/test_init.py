import muid

def test_mnemonic():
    key = b'f601f291896bb66b8a3c3d783077713a'
    code = muid.mhash(key)
    memorable = muid.search(code)
    assert memorable == 'Shammy Llama'

EXAMPLES = [ {'hash': b'7ee707a1f085a6e154fb0db53adb33bf',
'key': b'e76a151fd160805e81ead4e14939a722',
'length': 11,
'pretty': 'Teetotal Fox'},
{'hash': b'56a33411a3ae7cfc95597911708358ad',
 'key': b'f601f291896bb66b8a3c3d783077713a',
 'length': 11,
 'pretty': 'Shammy Llama'},
{'hash': b'6ea176470adcff53855f04181bca1a1b',
 'key': b'fb74baf628d43892020d803614f91f29',
 'length': 11,
 'pretty': 'Healthy Toad'},
{'hash': b'a3e76457c0de70a153e82067845f1527',
 'key': b'769adf0f307181e4ab2bc4c1b991cdc6',
 'length': 11,
 'pretty': 'Amethyst Cod'},
{'hash': b'1eadab1eb0acd26b3a5262c6d2bbcc4c',
 'key': b'5ac8e9f7e58181a384951460e8da1a73',
 'length': 11,
 'pretty': 'Leadable Boa'},
{'hash': b'105ab1ef1ea6ab3e85743e028f42847e',
 'key': b'30599b096bc5751c311ea6e15e306c86',
 'length': 11,
 'pretty': 'Losable Flea'},
{'hash': b'6ea7ab1ef1439f049f373bb514eee133',
 'key': b'0cff4edfbba6eeb21f18b565c892986f',
 'length': 11,
 'pretty': 'Heatable Fly'},
{'hash': b'd0771e53e1776fcb2d5f227ce42ee1ee',
 'key': b'63fe32ad7c0aaf0dc8d8835d84fe46e8',
 'length': 11,
 'pretty': 'Dottle Smelt'} ]


def test_many():
    for example in EXAMPLES:
        animal = muid.animal(example['key'])
        assert animal==example['pretty']