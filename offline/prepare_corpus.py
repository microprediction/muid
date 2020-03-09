import nltk
nltk.download('words')
nltk.download('averaged_perceptron_tagger')
from nltk.corpus import words

def select_adjectives(words):
    return [w for w, t in nltk.pos_tag(words) if t in ['JJ', 'JJR', 'JJS']]

def select_nouns(words):
    return [w for w, t in nltk.pos_tag(words) if t in ['NN', 'NNS', 'NNP', 'NNPS']]

def select_adverbs(words):
    return [w for w, t in nltk.pos_tag(words) if t in ['RBR', 'RBS']]

def select_verbs(words):
    return [w for w, t in nltk.pos_tag(words) if t in ['VB', 'VBG']]

def to_readable_hex(code):
    """ Make hex a little more readable """
    return code.replace('0', 'o').replace('1', 'l').replace('2', 'z').replace('3', 'm').replace('4', 'y').replace(
        '5', 's').replace('6', 'h').replace('7', 't').replace('8', 'x').replace('9', 'g')

def from_readable_hex(readable):
    """ Convert back to valid hex characters """
    return readable.replace('o', '0').replace('l', '1').replace('z', '2').replace('m', '3').replace('y','4').replace(
        's', '5').replace('h', '6').replace('t', '7').replace('x', '8').replace('9', 'g')

import requests
ANIMALS = requests.get('https://gist.githubusercontent.com/atduskgreg/3cf8ef48cb0d29cf151bedad81553a54/raw/82f142562cf50b0f6fb8010f890b2f934093553e/animals.txt').text.split('\n')

def animals_of_len(k):
    return [ a.lower() for a in ANIMALS if len(a)==k and not a=='list' ]


def corpus(max_len=15):
    cp = dict()
    for k1 in range(3,12):
        for k2 in range(3,max_len-k1):
            cp_ = dict( [ (word,(k1,k2)) for word in corpus_pairs(k1,k2) ] )
            cp.update(cp_)
    return cp



def corpus_pairs( k1, k2, readable=False, separator='' ):
    """ Subset of memorable hexadecimal strings of length 9+k including the hyphen """
    valid_chars = 'olzmyshtxgabcdef'
    words_len_k1 = [w for w in words.words() if len(w) == k1 and all(c in valid_chars for c in w)]
    adjectives = select_adjectives(words_len_k1)
    adverbs = select_adverbs(words_len_k1)
    hadjectives = [from_readable_hex(w) for w in adjectives]
    hadverbs = [from_readable_hex(w) for w in adverbs]
    hanimals = [from_readable_hex(a) for a in animals_of_len(k2)]
    hex_corpus = [ w1+separator+w2 for w1 in hadjectives+hadverbs for w2 in hanimals ]
    return [to_readable_hex(w) for w in hex_corpus] if readable else hex_corpus


for k1 in range(4,8):
    for k2 in range(3,8):
        for suffix in ['','_readable']:
            with open('animals_'+str(k1)+'_'+str(k2)+suffix+'.txt','w') as f:
                for w in corpus_pairs(k1=k1,k2=k2,readable=(suffix=='_readable'),separator=' '):
                    f.write('%s\n' % w)


import json
crps = corpus()
with open('animals.json','w') as f:
    json.dump(crps,f)
