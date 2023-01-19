from Trivium import Trivium
import random

ROUNDS = 50
LENGTH = 20

def generateRandKeys(no_of_keys):
    key_set = []
    for i in range(no_of_keys):
        key = ""
        for b in range(80):
            key += str(random.randint(0, 1))
        key_set.append(key)
    return key_set

def isOfPeriod(s, period):
    N = len(s)

    for idx in range(1, period+1):
        comp_with = s[idx-1]
        j = idx - 1 + period
        while j < N:
            if s[j] != comp_with:
                return False
            j += period
            
    return True

if __name__ == "__main__":
    rand_key_set = generateRandKeys(ROUNDS)
    rand_iv_set = generateRandKeys(ROUNDS)
    
    for key, iv in zip(rand_key_set, rand_iv_set):
        myTrivium = Trivium(key, iv)
        output_stream = myTrivium.getBits(2**(LENGTH+1))
        
        period = 2**LENGTH
        for p in range(1, 2**LENGTH):
            if isOfPeriod(output_stream, p):
                period = p
                break 
        
        if period < 2**LENGTH:
            print(f"[Failure] For key={key}, iv={iv}, Trivium has period of {period}.")
        else:
            print(f"[Success] For key={key}, iv={iv}, Trivium has period at least 2^{LENGTH}.")


    