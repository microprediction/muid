import requests, ring

CORPUS = requests.get('https://raw.githubusercontent.com/microprediction/muid/master/offline/animals.json').json()
BCORPUS = dict( [ (k.encode('ascii'),v) for k,v in CORPUS.items() ])

def to_readable_hex(word):
    """ Make hex a little more readable """
    return word.replace('0', 'o').replace('1', 'l').replace('2', 'z').replace('3', 'm').replace('4', 'y').replace(
        '5', 's').replace('6', 'h').replace('7', 't').replace('8', 'x').replace('9', 'g')

def from_readable_hex(word):
    """ Convert back to valid hex characters """
    return word.replace('o', '0').replace('l', '1').replace('z', '2').replace('m', '3').replace('y',
                                                                                                    '4').replace(
        's', '5').replace('h', '6').replace('t', '7').replace('x', '8').replace('9', 'g')

