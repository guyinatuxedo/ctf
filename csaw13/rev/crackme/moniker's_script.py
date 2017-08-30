from __future__ import print_function
from multiprocessing import Process, Queue
from math import *
import time
import thread
import random

#target = 0xef2e3558

chars = []
i=0x0
while(i<256):
    chars.append(chr(i))
    i=i+1
i=0x0

def run(thread_name):
    while(1):
        test = ''.join(random.choice(chars) for x in range(6))
        i = 0x0
        x = 0x0
        c = 0x0
        l = 1337
        for j in test:
            c=ord(test[i])
            x=(32*l)+c 
            i=i+1
            l+=x 
        if(abs(int(hex(l)[-9:],16)-4012782936)<256):
            print ("test: " +':'.join(x.encode('hex') for x in test))
            print ("difference: " + str(abs(int(hex(l)[-9:],16)-4012782936)))
            break

num_threads = 8

queue = Queue()

process = [Process(target = run, args = (k,))
                    for k in range(10)]

for p in process:
    p.start()
    
for p in process:
    p.join()

results = [queue.get() for p in process]
