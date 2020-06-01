from muid.explanation import TITLE, EXPLANATION, LEVEL12, LEVEL13, RANT
import pprint, time, binascii, os, random
from muid.corpus import BCORPUS, to_readable_hex, pretty
from muid.crypto import bhash



#------------------------------------------------------------------
#     A mining algorithm you are welcome to improve
#------------------------------------------------------------------

def create(difficulty=8, with_report=False):
    """ Find a MUID
         difficulty:  int  minimum length of the memorable part of the hash
    """
    dffclty = difficulty
    if dffclty>=13:
        print("Creating a difficult MUID. This may take days or weeks.")
    quota = 100000000
    count = 0
    while True:
        report, dffclty, count = mine_once(dffclty, count, quota)
        if report:
            return report if with_report else report[0]["key"]

def mine(timeout=1000000000,skip_intro=False,quota=16, start_difficulty=6 ):
    """ Mine for keys of increasing length """
    start_time = time.time()
    difficulty = start_difficulty
    count = 0
    announced_12 = False
    announced_13 = False
    TWELVE = 12

    print(TITLE,flush=True)
    if skip_intro:
        print( "Starting to mine ...", flush=True )
        print( "Control-C to stop ... ")
        print( " ")
    else:
        # Explain while mining
        found_during_explanation = list()
        for ln in EXPLANATION:
            print(ln,flush=True)
            for _ in range(int(len(ln)/3)):
                found, difficulty, count = mine_once(difficulty,count,quota)
                found_during_explanation.extend(found)

        for q in found_during_explanation:
            time.sleep(3)
            pprint.pprint(q)
            print(" ",flush=True)

    # Then keep going until level 12
    while time.time()<start_time+timeout and difficulty<TWELVE:
        found, difficulty, count = mine_once(difficulty,count,quota)
        if found:
            print(" ", flush=True)
            pprint.pprint(found[0])
            print(" ", flush=True)
            time.sleep(1)

    if difficulty >= TWELVE and not (announced_12):
        print(LEVEL12, flush=True)
        announced_12 = True

    # Rant while mining once level 12 is reached
    for ln in RANT:
        if not (skip_intro):
            print(ln, flush=True)
        for _ in range(int(len(ln) / 3)):
            found, difficulty, count = mine_once(difficulty, count, quota)
            if found:
                print(" ", flush=True)
                pprint.pprint(found[0])
                print(" ", flush=True)

    # Then go until timeout
    while time.time()<start_time+timeout:
        found, difficulty, count = mine_once(difficulty, count, quota)
        # Then back to work ...
        if difficulty >= TWELVE+1 and not announced_13:
            print(LEVEL13, flush=True)
            announced_13 = True
        if found:
            print(" ", flush=True)
            pprint.pprint(found[0])
            print(" ", flush=True)
        if random.choice(range(1000))==1:
            print("Never give up. Never surrender. ",flush=True )


def mine_once(difficulty,count,quota):
    # Only one batch
    keys         = [ binascii.b2a_hex(os.urandom(16)) for _ in range(100000) ]
    hashed_keys  = [bhash(key) for key in keys]
    short_codes  = [ hk[:difficulty]   for hk in hashed_keys ]
    longer_codes = [ hk[:difficulty+1] for hk in hashed_keys]
    candidates   = dict( zip(short_codes,keys) )
    long_candidates = dict( zip( longer_codes, keys) )

    if any( code in BCORPUS for code in short_codes ):
        for c,key in candidates.items():
            ks = BCORPUS.get(c)
            if ks is not None:
                report = report_finding(key=key,c=c,ks=ks)
                count = count+1
                if count==quota:
                    difficulty = difficulty+1
                    count = 0
    elif any( longer_code in BCORPUS for longer_code in longer_codes ):
        for c,key in long_candidates.items():
            ks = BCORPUS.get(c)
            if ks is not None:
                report = report_finding(key=key,c=c,ks=ks)
                difficulty = difficulty+1
                count = 1
    else:
        report = []
    return report, difficulty, count


def report_finding(key,c,ks):
    k1, k2 = ks
    prtty = pretty(code=c, k1=k1, k2=k2)
    longest_found = k1 + k2
    full_code = bhash(key)
    response = [{"length": longest_found, "pretty": prtty, "key": key, "hash": full_code}]
    return response
