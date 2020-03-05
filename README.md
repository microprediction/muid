# muid
Mine Memorable Unique Identifiers 

### Wait you say ... this cannot make sense!

Memorable unique identifiers are a provocative misnomer. When generating 
unique identifiers such as privately used keys, memorability is antithetical
to uniqueness. 

MUIDs might be termed "hash-memorable" identifiers. They form a subset of UUIDs whose SHA-1 hashes are memorable, in a manner in which 
this open source code makes precise. 

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

It is trivial to mine for MUIDs and the rates are way way better. 

    
    muid.mine(min_len=11)
    
The official difficulty 

    min_len = int(requests.get("http://www.microprediction.com/config.json").json()['min_len'])
    

### Cashing in 

Currently you can sell MUID's by establishing an Algorithmia account at https://algorithmia.com/signup and then 
supplying MUID's to one of the following buyers. 

  | Difficulty |  Bid  |  Buyer                                                      |
  |------------|-------|-------------------------------------------------------------|
  | min_len=11 | 7c    | https://algorithmia.com/algorithms/microprediction/mverify  |

The difficulty of 11 is only a guide and may have been updated. You can get it from: 

    min_len = int(requests.get("http://www.microprediction.com/config.json").json()['min_len'])

Good luck! 

# Example application 

Memorable unique identifiers are used at www.microprediction.com to circumvent the need to maintain a lookup
between user keys and public user identities. New users burn themselves a 
has-memorable private identity and the memorable part of the hash appears on leaderboards.
 
The more difficult the mnemonic (i.e. longer) the more drawdown leeway they are granted. 

The benefits of using MUIDs in this context are:

- No need for central registration or key provision
- No ability to generate vast numbers of keys 
- Enforced computational timeout after drawdown makes other Sybil style attacks harder.  
 
We hope you have your own uses and would love to hear about them. Many applications can benefit
from "one less join". 

## Discussion 

https://github.com/microprediction/muid/issues or https://algorithmia.com/algorithms/microprediction/mverify/discussion
    
# Technical details 

### Hash 
We use a version of SHA-1 hash, namely
 
    code = str(uuid.uuid5(uuid.NAMESPACE_DNS, key))
 
which takes UUID's to string representation of the hash of the UUID. 

### Readable hex
    
The image of mhash contains only strings with characters a,b,e,d,e,f plus digits. That's not such a fun game of scrabble so 
muid introduces the notion of readable hex strings. These are the image under the map which swaps out characters as follows:

  | Hex  | Readable  |
  |------|-----------|
  | 5    |s          |
  | 1    |l          |
  | 7    |t          |
  | 0    |o          | 
  
   
## Collisions are a non-issue 

It is well appreciated that approximately 2.71 quintillion uuid4() can be generated before the risk of collision exceeds fifty percent (Wikipedia). 

#### Collision probabilities for muid 

Because MUID's are a tiny subset of UUID's, the collision probabilities per muid are higher but still small typically.

- With min_len=8 say, then there will typically be a few million attempts per muid generated. Thus one can generate a trillion muid before
any there is any risk of collision in the underlying uuid's (whether used or not) because a few quintillion / a few million = one trillion. 

This is a defensive calculation. 
 
It is also a somewhat irrelevant calculation and there is a stronger reason not to worry. 

Your users will be limited
in their capacity to produce muid's in a way that they are not limited with uuid's. A moment's reflection should convince you
that the computational capacity required to create MUID collisions over any interval of time is at least as large as the computational capacity employed 
to create UUID collisions. 

So stop worrying and love MUIDs. 

#### For the true worry warts ...

If you are not convinced by logic, in place of the default method=uuid.uuid4 you can supply a method of generating candidate unique identifiers with
even longer string representations - for example concatenating a UUID with the last min_len characters of another independent UUID. 
 
 
# Scrabble fans 
  
If you enjoy generating words using vowels a,c,e,o and consonants c,b,d,f,s,l,t then please do contribute pull requests for https://github.com/microprediction/muid/blob/master/muid/corpus.py



