import sys, muid

if __name__=="__main__":
    api_key = sys.argv[0]
    algo    = sys.argv[1]
    if len(sys.argv)>2:
        email = sys.argv[2]
    else:
        email = None
    muid.mine_and_sell(timeout=60*60*24*30, algo=algo, api_key=api_key, email=email )
