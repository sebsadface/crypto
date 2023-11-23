from sympy import isprime
from timeit import default_timer as timer
import math

# The RSA modulus N
N = 1233626153975765256832069105719625449453005007655647000923233367120767290238588667397052161653352801437540471197470570083267

# Function to find the factors
def factors(N):
    # Approximate square root of N
    approx_sqrt_N = int(math.isqrt(N))

    # Search for prime factors near the square root of N
    for i in range(approx_sqrt_N, 1, -1):
        print("Trying i = ", i)
        if N % i == 0 and isprime(i):
            # double check
            if isprime(N // i) and i * (N // i) == N:
                return i, N // i

    print("Error: no factors found")
    return None, None

# Find P and Q
timer_start = timer()
P, Q = factors(N)
timer_end = timer()
print("P = ", P, "Q = ", Q, "Time = ", timer_end - timer_start)
