from muid.mining import mine_once
import timeit

SECONDS_IN_MONTH=60*60*24*30.5
MONTHLY_COST=10.0

t0 = timeit.timeit(setup="from muid.mining import mine_once", stmt="mine_once(difficulty=9,count=0,quota=1)", number=2 ) /2

def mean_creation_time(difficulty):
    reps = 20 if difficulty<=11 else 10
    return timeit.timeit(setup="from muid.mining import create", stmt="create(difficulty="+str(difficulty)+")", number=reps ) / reps

def value(mean_creation_time):
    return MONTHLY_COST*mean_creation_time/SECONDS_IN_MONTH

if __name__=="__main__":
    # This will take quite a while to run
    value8 = 2.1*1e-5
    for difficulty in range(6,11):
        tau = mean_creation_time(difficulty)
        print((difficulty,tau,value(tau),value(tau)/(value8*16**(difficulty-8))))
