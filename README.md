# muid
Memorable Unique Identifiers 

### Wait you say ... that's an oxymoron

Memorable unique identifiers are a provocative misnomer. When generating 
unique identifiers such as privately used keys, memorability is antithetical
to uniqueness. MUIDs might be better termed "hash-memorable" identifiers. They form a subset
of UUIDs whose SHA-256 hashes are memorable. See the https://vimeo.com/397352413 for further explanation. 
 
# Start mining now 

Just want to mine? Run this bash script. 

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/microprediction/muid/master/examples/mine_from_venv.sh)"
 
The script will explain itself and the motivation, as it mines. If it doesn't work then maybe
try 

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew install python
    
although we'd rather not get into a debate about the "best" way to install Python on a mac. 
 
# Sponsor a statistician 

If you find a spirit animal of length 13 or more you can make the day of someone looking to
enter a worldwide statistics contest, to be announced Apr 1st, 2020. The clock is ticking.  
 
# Using the library directly

As per https://muid.readthedocs.io/en/latest/ ...

### Install 

    pip install muid

### MUIDs are just like UUIDs  (uuid.uuid4)
 
    import muid
    key  = muid.muid4(min_len=8)  
    
Only they take much, much longer to generate because ...
 
### ... the SHA-256 hash is memorable 
    
Try this:
    
    print( muid.mhash(key) )    
    
Don't see it yet? Look closer. Here's an example I just happenned to have lying around:

    f01dab1eca70403aa0c700f6c29596c4

This reads a bit like:

    Foldable Cat  
    
# Mining 

It is trivial to mine for MUIDs. 
    
    muid.mine()
    
At time of writing, mining MUIDs is roughly one order of magnitude more profitable than mining bitcoin even if you use this 
lousy library to do your mining. With a little work, you should be able to mine with 100x the economics of bitcoin ... at least
for a while! 
    
# Applications 
 
We hope you have your own uses and would love to hear about them. Many applications can benefit
from one less join. 
    
# Implementation decisions 

We welcome thoughtful suggestions at https://github.com/microprediction/muid/issues 

### Choice of hash    

    muid.mhash() 
    
Uses SHA-256 hash from hashlib.sha256 

### Readable hex
    
Hex strings are just a,b,e,d,e,f plus digits and hyphens, which makes for a sucky game of scrabble. We introduce readable
hex as follows: 

    word.replace('0', 'o').replace('1', 'l').replace('2', 'z').replace('3', 'm').replace('4', 'y').replace(
        '5', 's').replace('6', 'h').replace('7', 't').replace('8', 'x').replace('9', 'g')

which is to say

  | Hex  | Human| Hex | HUman   | Hex  | Human |
  |------|------|-----|---------|------|-------|
  | 1    |l     | 5   | s       | 9    | g     |
  | 2    |z     | 6   | h       | 0    | o     |
  | 3    |m     | 7   | t       |      |       |
  | 4    |y     | 8   | x       |      |       |
  
     
### Collisions (forgetaboutit) 

It is well appreciated that approximately 2.71 quintillion uuid4() can be generated before the risk of collision exceeds fifty percent (Wikipedia). Thus UUID collisions
are a non-issue. But since an MUID collision requires an underlying collision in UUIDs which are generated while mining, a moment's reflection should convince the reader
that the computational capacity required to create MUID collisions over any interval of time is at least as large as the computational capacity employed 
to create UUID collisions. In short, the thing to worry about is the relatively short supply of MUIDs (an obvious limitation) not collisions between them. 
 
### Stupid dog trick

https://vimeo.com/396819347




