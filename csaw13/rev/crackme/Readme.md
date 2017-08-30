# crackme

Let's take a look at the binary:

```
crackme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3ec5ee1f1d99fc4878737c38eec4468eff371802, stripped
```

So we can see it is a 32 bit elf. Let's take a look at the main function in IDA:

```
void __cdecl __noreturn main()
{
  unsigned int time_int; // eax@1
  int socket; // eax@2

  time_int = time(0);
  srand(time_int);
  socket = listen_func(0xD431u);
  fork_func(socket, name, (int)user_interface_func);
}
```

Looking at this function, it appears that it listens on a port, then forks it over to the function `user_interface_func`. Note that it is just passing the address of `user_interface_func` as an int. Let's take a look at the the `fork_func`:

```
void __cdecl __noreturn fork_func(int fd, char *name, int user_interface_func)
{
  int socket; // [sp+14h] [bp-14h]@1
  int random_int; // [sp+14h] [bp-14h]@2
  __pid_t fork; // [sp+18h] [bp-10h]@2
  int status; // [sp+1Ch] [bp-Ch]@5

  while ( 1 )
  {
    do
    {
      do
        socket = accept(fd, 0, 0);
      while ( socket == -1 );
      random_int = random_func(socket);
      fork = ::fork();
    }
    while ( fork == -1 );
    if ( !fork )
    {
      chdir_setid(name);
      close(fd);
      alarm(0x10u);
      status = ((int (__cdecl *)(_DWORD))user_interface_func)(random_int);
      close(random_int);
      exit(status);
    }
    close(random_int);
  }
}
```

So here we can see that it checks to see if the network connection is good, then continues with the fork. Before it executes the program, a function I named `chdir_setid` is called. Let's take a quick look at that:

```
int __cdecl chdir_setid(char *name)
{
  int result; // eax@6
  struct passwd *user_name; // [sp+1Ch] [bp-Ch]@1

  user_name = getpwnam(name);
  if ( !user_name )
    exit(-1);
  if ( setgroups(0, 0) == -1
    || setgid(user_name->pw_gid) == -1
    || setuid(user_name->pw_uid) == -1
    || (result = chdir(user_name->pw_dir), result == -1) )
  {
    exit(-1);
  }
  return result;
}
```

Looking at this code, we see that it attemptes to set the `uid` (user id), `gid`, and change the directory. If the program can't do that (can be caused because the user doesn't exist), then the binary will crash, so we need to find out what it needs so we can actually run the binary. For this, I set a breakpoint at `0x08048bb0` which will land us at this line of code:

```
  user_name = getpwnam(name);
```

Since this binary is a server that listens on a port, we will need two terminals to analyze it

gdb:
```
gdb-peda$ b *0x08048bb0
Breakpoint 1 at 0x8048bb0
gdb-peda$ r
Starting program: /Hackery/ancient/13csaw/rev/crackme/crackme 
[New process 14575]
[Switching to process 14575]
```

client:
```
$	nc 127.0.0.1 54321
```

gdb:
```
[----------------------------------registers-----------------------------------]
EAX: 0xf7fb2cc0 --> 0x804c008 ("crackme")
EBX: 0x0 
ECX: 0xffffffc0 
EDX: 0x0 
ESI: 0x1 
EDI: 0xf7fb1000 --> 0x1b5db0 
EBP: 0xffffd0d8 --> 0xffffd108 --> 0xffffd138 --> 0x0 
ESP: 0xffffd0b0 --> 0x8049130 ("crackme")
EIP: 0x8048bb0 (mov    DWORD PTR [ebp-0xc],eax)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048ba5:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048ba8:	mov    DWORD PTR [esp],eax
   0x8048bab:	call   0x80486d0 <getpwnam@plt>
=> 0x8048bb0:	mov    DWORD PTR [ebp-0xc],eax
   0x8048bb3:	cmp    DWORD PTR [ebp-0xc],0x0
   0x8048bb7:	jne    0x8048bc5
   0x8048bb9:	mov    DWORD PTR [esp],0xffffffff
   0x8048bc0:	call   0x80487c0 <exit@plt>
[------------------------------------stack-------------------------------------]
0000| 0xffffd0b0 --> 0x8049130 ("crackme")
0004| 0xffffd0b4 --> 0x0 
0008| 0xffffd0b8 --> 0x0 
0012| 0xffffd0bc --> 0xf7fb1000 --> 0x1b5db0 
0016| 0xffffd0c0 --> 0xffffd108 --> 0xffffd138 --> 0x0 
0020| 0xffffd0c4 --> 0xf7fee020 (pop    edx)
0024| 0xffffd0c8 --> 0x0 
0028| 0xffffd0cc --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "crackme" hit Breakpoint 1, 0x08048bb0 in ?? ()
gdb-peda$ x/x $eax
0xf7fb2cc0:	0x0804c008
gdb-peda$ x/s 0x0804c008
0x804c008:	"crackme"
```

So the user we need to add in order to run the binary is `crackme`:

```
$	sudo adduser crackme
```

Also when you run the binary, you need to make sure you do it with the permissions to change the `uid` and `gid` to `crackme`, otherwise it will fail. Now that we took care of that, let's take a look at the `user_interface_func`.

```
int __cdecl user_interface_func(int socket)
{
  int result; // eax@2
  int key_file; // ST18_4@4
  int v3; // edx@7
  unsigned int characters_received; // [sp+14h] [bp-214h]@1
  _BYTE input_text[256]; // [sp+1Ch] [bp-20Ch]@1
  char key_buf[256]; // [sp+11Ch] [bp-10Ch]@4
  int v7; // [sp+21Ch] [bp-Ch]@1

  v7 = *MK_FP(__GS__, 20);
  send_text_func0(socket, "Enter registration code: ");
  characters_received = input_text_func(socket, (int)input_text, 255, 10);
  if ( characters_received == -1 )
  {
    result = 0;
  }
  else
  {
    input_text[characters_received] = 0;
    if ( enc(input_text) == 0xEF2E3558 )
    {
      send_text_func0(socket, "Thank you, valued customer!\n");
      key_file = open("key", 0);
      key_buf[read(key_file, key_buf, 0x40u)] = 0;
      send_text_func1(socket, "Your key is: %s\n", key_buf);
    }
    else
    {
      send_text_func1(socket, "Invalid registration code.\n");
    }
    result = 0;
  }
  v3 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```

So looking at this, we can see that it prompts the user for a registration code. It then takes that code and runs it through the `enc` function. If the output matches the hex string `0xEF2E3558`, then it reads from a file called `key` and prints out it's contents. When the competition happened they had a copy of this ELF running on a server, and you had to connect to it and have it pass the check in order to get the flag (which they named `key`). So let's take a look at the `enc` function, so we can figure out how to get the output we need:

```
signed int __cdecl enc(unsigned __int8 *input)
{
  int x; // ST0C_4@3
  unsigned __int8 current_char; // [sp+3h] [bp-Dh]@1
  signed int accumulator; // [sp+4h] [bp-Ch]@1
  unsigned __int8 *input_trans; // [sp+8h] [bp-8h]@2

  current_char = *input;
  accumulator = 1337;
  if ( *input )
  {
    input_trans = input;
    do
    {
      x = 32 * accumulator + current_char;
      current_char = (input_trans++)[1];
      accumulator += x;
    }
    while ( current_char );
  }
  return accumulator;
}
```

So we can see here, a function that runs once for each character that it receives. For each iteration it takes the decimal value of the current character, and adds it to 32 times the accumulator (starts off as `1337`). It then adds that value to the accumulator, switches to the next letter, then starts again. It effictively translates to the following python code:

```
input = "input_text_goes_here"
#input = "\x89\xf5\xd0\xb4\xb3\xfe\x90\x52\x48\x82"

i = 0x0
x = 0x0
current_char = 0x0
accumulator = 1337
for j in input:
	current_char = ord(input[i])
	x = (32 * accumulator) + current_char
	print "x: " + hex(x)
	i += 1
   	accumulator += x
	print "accumulatoreet: " + hex(accumulator)
end = hex(accumulator)

print end

#victory: 0xEF2E3558
```

One thing to say, we don't have to get the whole output to be equal to `0xEF2E3558`, we just have to get it to end with that hex string (set a breakpoint for `0x08048f80` to see for yourself). With that the next part is finding an input tot that python script, which will give us an output that ends with `0xEF2E3558`. I had a lot of difficulty figuring out how to do it, so I handed it off to my team's crypto expert moniker (here's his github https://github.com/m0nik3r). He essentially wrote a script that just brute forced it. The script doesn't output exact matches however when you run it through the encryption process, subtract the difference from the output you got and the desired output, and adjust the input accordingly, you will get the correct input:

```
from __future__ import print_function
from multiprocessing import Process, Queue
from math import *
import time
import thread
import random

#target = 0xef2e3558

chars = []
i=0x0
while(i<256):
    chars.append(chr(i))
    i=i+1
i=0x0

def run(thread_name):
    while(1):
        test = ''.join(random.choice(chars) for x in range(6))
        i = 0x0
        x = 0x0
        c = 0x0
        l = 1337
        for j in test:
            c=ord(test[i])
            x=(32*l)+c 
            i=i+1
            l+=x 
        if(abs(int(hex(l)[-9:],16)-4012782936)<256):
            print ("test: " + test)
            print ("difference: " + str(abs(int(hex(l)[-9:],16)-4012782936)))
            break

num_threads = 10

queue = Queue()

process = [Process(target = run, args = (k,))
                    for k in range(10)]

for p in process:
    p.start()
    
for p in process:
    p.join()

results = [queue.get() for p in process]
```


So after adjusting the output of one of this script's outputs, we now that we know that an input that works is `\x89\xf5\xd0\xb4\xb3\xfe\x90\x52\x48\x82` (there are multiple correct inputs), we can just write a little python to send that:

```
#Import pwntools
from pwn import *

#Establish the remote connection
target = remote('127.0.0.1', 54321)

#Establish the desired input
solution = "\x89\xf5\xd0\xb4\xb3\xfe\x90\x52\x48\x82"

#Send it
target.sendline(solution)

#Drop to an interactive shell
target.interactive()
```

Start the server:
```
$	sudo ./crackme
```

Solve the challenge:
```
python solve.py 
[+] Opening connection to 127.0.0.1 on port 54321: Done
[*] Switching to interactive mode
Enter registration code: Thank you, valued customer!
Your key is: x\x84\x0
[*] Got EOF while reading in interactive
```

So you can see we solved the challenge. Since I don't have the key file (and since the server is no longer up) I won't be able to print it, but I found it online and it's `Flag: day 145: they still do not realize this software sucks` (grabbed from http://digitaloperatives.blogspot.com/2013/09/csaw-ctf-2013-reversing.html). Thanks again to moniker for his help with this problme (checkout his github https://github.com/m0nik3r),  Just like that, we Captured the Flag!
