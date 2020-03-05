import uuid, time
from muid.corpus import Corpus

def muid4( min_len=8, timeout=60*60 ):
    return Memorable.muid(method=uuid.uuid4, min_len=min_len, timeout=timeout)

def muid1( min_len=8, timeout=60*60 ):
    return Memorable.muid(method=uuid.uuid1, min_len=min_len, timeout=timeout)

def mhash(key):
    return Memorable.hash(key)

def mpretty(phrase):
    return Memorable.pretty(phrase)

def mine(min_len=8,timeout=1000000000):
    gen = Memorable.key_generator(min_len=min_len, timeout=timeout, verbose=True)
    for key in gen:
        print(key, flush=True)

def mnemonic(key):
    return Memorable.mnemonic(key=key)

def mverify(key,min_len=8):
    return Memorable.verify(key=key,min_len=min_len)

class Memorable(Corpus):

    @staticmethod
    def muid(min_len, timeout, method=None):
        if method is None:
            method = uuid.uuid4
        gen = Memorable.key_generator(min_len=min_len, timeout=timeout, method=method)
        return next(gen)

    @staticmethod
    def mnemonic(key,separator=' ',capitalize=True):
        """ Reveal the memorable part of a key hash, if any """
        result = Memorable.verify(key=key,verbose=True,min_len=Memorable.min_word_len())
        if result['result']:
            return Memorable.pretty(result['long'],separator=separator,capitalize=capitalize)



    @staticmethod
    def verify(key, min_len, verbose=False):
        if isinstance(key,str) and len(key):
            code = Memorable.hash(key)
            hcode = Memorable.to_readable_hex(code)
            long  = Memorable.longest_word_or_phrase(hcode)
            valid = len(long)>=min_len
        else:
            valid, long = False, ''
        return valid if not verbose else {"result":valid,"long":long}

    @staticmethod
    def hash(key):
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, key))

    @staticmethod
    def is_readable_hex(s):
        """ The set of strings refered to as henglish is the image of hex strings under the map which swaps (5->s,1->l,7->t,0->o) """
        return all( c in 'ol234s6t89abcdef-' for c in s)

    @staticmethod
    def to_readable_hex(code):
        """ Make hex a little more readable """
        return code.replace('0', 'o').replace('1', 'l').replace('5', 's').replace('7', 't')

    @staticmethod
    def from_readable_hex(readable):
        """ Convert back to valid hex characters """
        return readable.replace('o', '0').replace('l', '1').replace('s', '5').replace('t','7')

    @staticmethod
    def longest_word(readable):
        assert Memorable.is_readable_hex(readable), "Convert to readable hex first "
        phrase_sans = readable.replace('-', '')
        words_found = list()
        k = Memorable.max_word_len()
        k_stop = Memorable.min_word_len()
        while not words_found and k>=k_stop:
            if phrase_sans[:k] in Memorable.words_of_len(k):
                return phrase_sans[:k]
            k = k-1

    @staticmethod
    def longest_phrase(readable):
        assert Memorable.is_readable_hex(readable), "Convert to readable hex first "
        phrase_sans = readable.replace('-', '')
        k=Memorable.max_phrase_len()
        pairs_found = list()
        while not pairs_found and k>=6:
            phrase_k = phrase_sans[:k]
            if phrase_k in Memorable.phrases_of_len(k):
                return phrase_k
            k = k-1

    @staticmethod
    def longest_word_or_phrase(readable):
        word_found   = Memorable.longest_word(readable) or ''
        phrase_found = Memorable.longest_phrase(readable) or ''
        return word_found if len(word_found)>len(phrase_found) else phrase_found

    @staticmethod
    def split(readable_phrase):
        """ Break pair (or singleton) back into two words (or one) """
        assert Memorable.is_readable_hex(readable_phrase), "Convert to readable hex first"
        phrase_sans = readable_phrase.replace('-', '')
        if Memorable.is_word(phrase_sans):
            return [ phrase_sans ]
        elif len(phrase_sans)>=2*Memorable.min_word_len() and (phrase_sans in Memorable.phrases_of_len(len(phrase_sans))):
            k = len(phrase_sans)
            parts = []
            k_min = Memorable.min_word_len()
            k1 = k_min
            while not parts and k1<=Memorable.max_phrase_len():
                w1 = phrase_sans[:k1]
                if w1 in Memorable.words()[k1]:
                    w2 = phrase_sans[k1:]
                    k2 = k-k1
                    if k2>=k_min and w2 in Memorable.words()[k - k1]:
                        parts = [w1,w2]
                k1 = k1+1
            return parts
        else:
            return None # Cannot split ...

    @staticmethod
    def pretty(readable_phrase, separator=' ', capitalize=False):
        """ Return a pretty version of a phrase such as:
                Foldable Cat
        """
        parts = Memorable.split(readable_phrase)
        cap_parts = [ part[0].upper()+part[1:] for part in parts ] if capitalize else parts
        return separator.join(cap_parts)

    @staticmethod
    def key_generator( method=None, min_len=7, timeout=5, verbose=False, batch_size=100 ):
        """ Returns generator that spits out valid keys whose hashes are recognizable Henglish words or word pairs

             method:   function returning a unique identifier  (e.g.  uuid.uuid4)
             timeout:  seconds

        """
        if method is None:
            method = uuid.uuid4
        start_time = time.time()
        num_attempts = 0
        assert Memorable.min_word_len() <= min_len <= Memorable.max_phrase_len()
        readable_phrases = Memorable.phrases_of_len(min_len) + Memorable.words_of_len(min_len)
        hex_phrases = [ Memorable.from_readable_hex(readable) for readable in readable_phrases ]
        while time.time()<start_time+timeout:
            num_attempts += batch_size
            uuids    = [ method() for _ in range(batch_size) ]
            codes    = [ Memorable.hash(str(uuid)) for uuid in uuids ]
            patterns = [ code.replace('-','')[:min_len] for code in codes ]
            found    = any( pattern in hex_phrases for pattern in patterns )
            if found:
                for pattern, uid in zip( patterns, uuids ):
                    if pattern in hex_phrases:
                        key      = str(uid)
                        code     = Memorable.hash(key)
                        hcode    = Memorable.to_readable_hex(code=code)
                        readable = Memorable.longest_word_or_phrase(hcode)
                        pretty   = Memorable.pretty(readable, separator=' ', capitalize=True)
                        if verbose:
                            yield {"length": len(readable), "pretty": pretty, "key": key, "hashed key": code,'num_attempts': num_attempts}
                        else:
                            yield key


