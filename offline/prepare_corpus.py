import nltk,json
nltk.download('words')
nltk.download('averaged_perceptron_tagger')
from nltk.corpus import words
import requests
from muid.corpus import from_readable_hex

pos = {''}

# Exclude words that are likely to offend
EXCLUDED_ADJECTIVES = ['sambo']
EXCLUDED_ANIMALS = ['booby']

def select_acceptable_first_words(words):
    """
    Currently included:
    FW    foreign    word
    NNPS  proper noun, plural ‘Americans’
    JJ    adjective ‘big’
    JJR   adjective, comparative ‘bigger’
    JJS   adjective, superlative ‘biggest’\
    RBR   adverb, comparative better
    RBS   adverb, superlative best
    VBG   verb, gerund / present participle taking
    VB    verb, base form take
    NNP   proper noun, singular ‘Harrison’
    # Discussed at https://medium.com/@gianpaul.r/tokenization-and-parts-of-speech-pos-tagging-in-pythons-nltk-library-2d30f70af13b
    """
    return [w for w, t in nltk.pos_tag(words) if t in ['NNPS','JJ', 'JJR', 'JJS','RBR','RBS','VB','VBG','FW','NNP'] and not w.lower() in EXCLUDED_ADJECTIVES]


ALL_ANIMALS = requests.get('https://gist.githubusercontent.com/atduskgreg/3cf8ef48cb0d29cf151bedad81553a54/raw/82f142562cf50b0f6fb8010f890b2f934093553e/animals.txt').text.split('\n')
ANIMALS = [ a for a in ALL_ANIMALS if not a in EXCLUDED_ANIMALS ]

def animals_of_len(k):
    return [ a.lower() for a in ANIMALS if len(a)==k and not a=='list' ]

def corpus(max_len=16, separator='', readable=False, capitalize=False):
    cp = dict()
    for k1 in range(3,12):
        for k2 in range(3,max_len-k1):
            cp_ = dict([(word,(k1,k2)) for word in corpus_len_k1_k2(k1, k2, readable=readable, separator=separator, capitalize=capitalize)])
            cp.update(cp_)
    return cp

def capitalize_maybe(word, capitalize=False):
    return word[0].upper()+word[1:] if capitalize else word

def corpus_len_k1_k2(k1, k2, readable=False, separator='', capitalize=False):
    """ Subset of memorable hexadecimal strings of length 9+k including the hyphen """
    valid_chars  = 'olzmyshtxgabcdef'
    words_len_k1 = [w for w in words.words() if len(w) == k1 and all(c in valid_chars for c in w)]
    first_words  = select_acceptable_first_words(words_len_k1)
    animals_k2   = animals_of_len(k2)
    if readable:
        return [capitalize_maybe(word=w1, capitalize=capitalize) + separator + capitalize_maybe(word=w2, capitalize=capitalize)for w1 in first_words for w2 in animals_k2]
    else:
        hex_animals     = [from_readable_hex(a) for a in animals_of_len(k2) if all(c in valid_chars for c in a)]
        hex_first_words = [from_readable_hex(w) for w in first_words]
        hex_corpus      = [w1 + separator + w2  for w1 in hex_first_words for w2 in hex_animals]
        return hex_corpus

crpsr = corpus(separator=' ',readable=True, capitalize=True)
with open('animals_readable.json','w') as g:
    json.dump(crpsr,g)

import json
crps = corpus()
with open('animals.json','w') as f:
    json.dump(crps,f)

