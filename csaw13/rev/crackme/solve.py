#Import pwntools
from pwn import *

#Establish the remote connection
target = remote('127.0.0.1', 54321)

#Establish the desired input
solution = "\x89\xf5\xd0\xb4\xb3\xfe\x90\x52\x48\x82"

#Send it
target.sendline(solution)

#Drop to an interactive shell
target.interactive()
