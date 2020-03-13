# muid
Memorable Unique Identifiers 

### Wait you say ... that's an oxymoron

Memorable unique identifiers are a provocative misnomer. When generating 
unique identifiers such as privately used keys, memorability is antithetical
to uniqueness. MUIDs might be better termed "hash-memorable" identifiers. They form a subset
of UUIDs whose SHA-256 hashes are memorable. See the https://vimeo.com/397352413 for further explanation. 
 
# Start mining now 

Just want to mine? 

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/microprediction/muid/master/examples/mine_from_venv.sh)"
 
If it fails you might need Python 3

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew install python
 
# Using the library directly

As per https://muid.readthedocs.io/en/latest/ ...

### Install 

    pip install muid
 
### Hash-memorability
    
    >>> muid.mhash(b'f601f291896bb66b8a3c3d783077713a')
    b'56a33411a3ae7cfc95597911708358ad'
    
Don't see it?

    >>> muid.pretty(b'56a33411a3ae7cfc95597911708358ad',k1=6,k2=5)
    'Shammy Llama'
 
### Validation 
 
    >>> muid.animal(b'f601f291896bb66b8a3c3d783077713a')
    'Shammy Llama'
    
    >>> muid.validate(b'f601f291896bb66b8a3c3d783077713a')
    True
    
### Mining

    >>> muid.mine()
    
    {'hash': b'56a33411a3ae7cfc95597911708358ad',
    'key': b'f601f291896bb66b8a3c3d783077713a',
    'length': 11,
    'pretty': 'Shammy Llama'}
    
    {'hash': b'6ea176470adcff53855f04181bca1a1b',
    'key': b'fb74baf628d43892020d803614f91f29',
    'length': 11,
    'pretty': 'Healthy Toad'}

    {'hash': b'a3e76457c0de70a153e82067845f1527',
    'key': b'769adf0f307181e4ab2bc4c1b991cdc6',
    'length': 11,
    'pretty': 'Amethyst Cod'}
    
Bequeath unwanted MUIDs to a worthy statistician. 

# Applications 
 
See the video at https://vimeo.com/397352413 for some motivation. 

We hope you have an application that can benefit from one less join. 
    
# Implementation decisions 

We welcome thoughtful suggestions at https://github.com/microprediction/muid/issues 

### Choice of hash    

We truncate the output of hashlib.sha256 

### Readable hex
    
  | Hex  | Human| Hex | HUman   | Hex  | Human |
  |------|------|-----|---------|------|-------|
  | 1    |l     | 5   | s       | 9    | g     |
  | 2    |z     | 6   | h       | 0    | o     |
  | 3    |m     | 7   | t       |      |       |
  | 4    |y     | 8   | x       |      |       |
  
     
# Miscellaneous 

### Collisions

MUID collision requires approximately the same computational capacity as UUID collision or more. 
 
### Stupid dog trick

https://vimeo.com/396819347




