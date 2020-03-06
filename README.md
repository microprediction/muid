# muid
Memorable Unique Identifiers 

### Wait you say ... that's an oxymoron

Memorable unique identifiers are a provocative misnomer. When generating 
unique identifiers such as privately used keys, memorability is antithetical
to uniqueness. MUIDs might be better termed "hash-memorable" identifiers. They form a subset of UUIDs whose SHA-256 hashes are memorable. 
 
# Usage 

As per https://muid.readthedocs.io/en/latest/ ...

### Install 

    pip install muid

### Just like uuid.uuid4() ... only it takes longer
 
    import muid
    key  = muid.muid4()  
 
### The SHA-1 hash is memorable 
    
    print( muid.mhash(key) )    
    
Don't see it yet? Look closer. Here's my example:

    f01dab1e-ca70-403a-a0c7-00f6c29596c4

And if that isn't clear already, then:

    >>print( muid.mnemonic( key ) )
    Foldable Cat  
    
The call muid.mnemonic uses a corpus of readable hex-like scrabble words to infer that only the first 11 characters
are intended to be memorable. 

### Verificaton 

    muid.verify(key,min_len=7)

# Mining 

It is trivial to mine for MUIDs. 
    
    muid.mine()
    
At time of writing, mining MUIDs is roughly one order of magnitude more profitable than mining bitcoin even if you use this 
lousy library to do your mining. With a little work, you should be able to mine with 100x the economics of bitcoin ... at least
for a while! 
    
### Cashing in 

Currently you can sell MUID's by establishing an Algorithmia account at https://algorithmia.com/signup and then 
supplying MUID's to one of the following buyers. 

  | Difficulty |  Bid  |  Buyer                                                      |
  |------------|-------|-------------------------------------------------------------|
  | min_len=11 | 7c    | https://algorithmia.com/algorithms/microprediction/mverify  |

The difficulty of 11 may be stale. Check muid.MIN_LEN or directly: 
obtained directly:

    min_len = int(requests.get("http://www.microprediction.com/config.json").json()['min_len'])

See also examples/mining_example.py  

# An example of the use of MUIDs 

Memorable unique identifiers are used at www.microprediction.com to circumvent the need to maintain a lookup
between private user keys and nom de plume's. New users burn themselves a 
has-memorable private identity and the memorable part of the hash appears on leaderboards. This prevents excessive churning of
keys and identities and the obvious gaming of the system that might occur in its absence. 
 
We hope you have your own uses and would love to hear about them. Many applications can benefit
from one less join. 
    
# Implementation decisions 

We welcome thoughtful suggestions at https://github.com/microprediction/muid/issues or https://algorithmia.com/algorithms/microprediction/mverify/discussion. 

### Choice of hash    

    muid.mhash() 
    
uses SHA-256 hash from hashlib.sha256, then maps the first half to a UUID style string via the uuid.UUID constructor.  

### Readable hex
    
The hash produces strings with characters a,b,e,d,e,f plus digits and hyphens. 

    Memorable.to_readable()
 
swaps out characters as follows:

  | Hex  | Readable  |
  |------|-----------|
  | 5    |s          |
  | 1    |l          |
  | 7    |t          |
  | 0    |o          | 
  
This leads to a reasonable but not a huge list of hex-like scrabble words. As an aside, if you enjoy
generating words using vowels a,c,e,o and consonants c,b,d,f,s,l,t then please do contribute pull requests for https://github.com/microprediction/muid/blob/master/muid/corpus.py

   
### Collisions (forgettaboutit) 

It is well appreciated that approximately 2.71 quintillion uuid4() can be generated before the risk of collision exceeds fifty percent (Wikipedia). Thus UUID collisions
are a non-issue. But since an MUID collision requires an underlying collision in UUIDs which are generated while mining, a moment's reflection should convince the reader
that the computational capacity required to create MUID collisions over any interval of time is at least as large as the computational capacity employed 
to create UUID collisions. In short, the thing to worry about is the relatively short supply of MUIDs (an obvious limitation) not collisions between them. 
 
  



