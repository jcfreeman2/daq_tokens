#!/usr/bin/env python3
import daq_tokens
import time

t = daq_tokens.acquire(daq_tokens.FRESH)
start = time.time()
for i in range(1000):
  t = daq_tokens.acquire(daq_tokens.FRESH)
diff = time.time() - start

print(f"{diff} ms/acquire")
