#!/usr/bin/env tdaq_python

from daq_tokens import acquire, verify, REUSE, FRESH
from time import time

# should use what is specified in TDAQ_TOKENS_ACQUIRE
# e.g. kerberos
t1_start = time()
t1 = acquire(FRESH)
t1_time = time() - t1_start

# Should use the refresh token
t2_start = time()
t2 = acquire(FRESH)
t2_time = time() - t2_start


t3_start = time()
t3 = acquire(REUSE)
t3_time = time() - t3_start

t4_start = time()
for i in range(1000):
    t4 = acquire(REUSE)
t4_time = time() - t4_start

print("1 = ",t1,t1_time,"sec")
print("2 = ",t2,t2_time,"sec")
print("3 = ",t3,t3_time,"sec")
print("4 = ",t4,t4_time/1000,"sec")
