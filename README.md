# ctf

This is where I store CTF writeups I've made. 

## Pwn

#### ROP Chain
+ x64: bkp16/pwn/simple-calc Basic ROP Chain, syscall to execve("/bin/sh", NULL, NULL), Wierd method of writing data to memory
#### Return 2 System
+ x86: TUCTF/guestbook  Infoleak, PIE, strcpy
#### Faking Inputs
+ x64: bkp16/pwn/complex-calc pass false pointer to free and not crash, pointer is to bss
