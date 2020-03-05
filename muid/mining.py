from muid.memorable import Memorable
import ring
import Algorithmia, requests

def mine(min_len=8,timeout=1000000000):
    gen = Memorable.key_generator(min_len=min_len, timeout=timeout, verbose=True)
    for report in gen:
        print(report, flush=True)

@ring.lru()
def official_difficulty():
    return int(requests.get('https://www.microprediction.com/config.json').json()["min_len"])

def mine_and_sell(timeout=60*60*24*30, algo='microprediction/motza', api_key=None, email=None):
    # Before running this do the following:
    #    (1) Sign up for algorithmia account at www.algorithmia.com/signup
    #    (2) Enter your Algorithmia API key below. See  https://algorithmia.com/developers/platform/customizing-api-keys#default-api-key
    #    (3) Publish a public algorithm on Algorithmia and set the price at 1000 credits.
    # More instructions at https://algorithmia.com/algorithms/microprediction/mverify/docs

    client = Algorithmia.client(api_key = api_key)
    gen = Memorable.key_generator(min_len=official_difficulty(), timeout=timeout, verbose=True)
    print("Difficulty set to "+str(official_difficulty()))
    for report in gen:
        print(report)
        key = report["key"]
        input = {'key':key, 'algoRef':algo}
        if email:
            input.update({"email":email})
        # Sell it ...
        client.algo('microprediction/mverify').pipe(input)

