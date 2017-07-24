This writeup references this writeup:
```
http://capturetheswag.blogspot.com.au/2015/09/csaw-2015-quals-ftp-re300-challenge.html
```

Let's take a look at the binary:
```
$	file ftp_0319deb1c1c033af28613c57da686aa7 
ftp_0319deb1c1c033af28613c57da686aa7: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=43afbcd9f4e163f002970b9e69309ce0f1902324, stripped
```

So we can see that it is a 64 bit elf. Let's see what the binary does:
```
$	./ftp_0319deb1c1c033af28613c57da686aa7 
[+] Creating Socket
[+] Binding
[+] Listening
[+] accept loop

```

So we can see that it is listening on a socket. Let's see what port it is listening on, using ltrace which monitors library function calls:
```
$	ltrace ./ftp_0319deb1c1c033af28613c57da686aa7 
__libc_start_main(0x402d2e, 1, 0x7ffe37f0c198, 0x402ed0 <unfinished ...>
signal(SIGALRM, 0x402d19)                        = 0
puts("[+] Creating Socket"[+] Creating Socket
)                      = 20
socket(2, 1, 0)                                  = 3
puts("[+] Binding"[+] Binding
)                              = 12
bzero(0x7ffe37f0c080, 16)                        = <void>
htons(0x2eec, 16, 16, 0x7ff7288278f0)            = 0xec2e
htons(0, 16, 16, 0x7ff7288278f0)                 = 0
bind(3, 0x7ffe37f0c080, 16, 0x7ffe37f0c080)      = 0
puts("[+] Listening"[+] Listening
)                            = 14
listen(3, 5, 0x7ff728af2760, 0x7ff7288278f0)     = 0
puts("[+] accept loop"[+] accept loop
)                          = 16
accept(3, 0x7ffe37f0c090, 0x7ffe37f0c068, 0x7ffe37f0c090
``` 

So we can see a htons call here, which converts the byte order to the network byte order (big endian), that is used on the hex string `0x2eec`:

```
htons(0x2eec, 16, 16, 0x7ff7288278f0)            = 0xec2e
```

Let's see if we can't run the server, and connect to it on port `0x2eec` (12012):

```
$	nc 127.0.0.1 12012
Welcome to FTP server
help
USER PASS PASV PORT
NOOP REIN LIST SYST SIZE
RETR STOR PWD CWD
user guy
Please send password for user guy
pass tux
Invalid login credentials
pwd
login with USER first
port
login with USER first
dewdq
login with USER first
^C
```

So we were able to connect to the server. However it looks like we will have to grab the credentials for a user to log in. Let's take a look at the code in IDA. We know that the string `invalid login credentials` is printed, so let;s look for that:

```
  if ( !strncasecmp("PASS", input, 4uLL) )
  {
    *(heap_struct + 40) = v6;
    hash_func(*(heap_struct + 40));
    if ( !strncmp(*(heap_struct + 32), "blankwall", 9uLL) && hash_func(*(heap_struct + 40)) == 0xD386D209 )
    {
      *(heap_struct + 1216) = 1;
      sub_4014F8(*heap_struct, "logged in\n");
      dword_604408 = 102;
    }
    else
    {
      sub_4014F8(*heap_struct, "Invalid login credentials\n");
      free(ptr);
    }
  }
```

So we can see that this is the section of code that deals with checking the password. It appears here that the only valid user is `blankwall`. It also looks like the password hash for the `blankwall` user is `0xD386D209`. Let's take a look at the password hashing function:

```
__int64 __fastcall hash_func(char *string_to_hash)
{
  int i; // [sp+10h] [bp-8h]@1
  int x; // [sp+14h] [bp-4h]@1

  x = 0x1505;
  for ( i = 0; string_to_hash[i]; ++i )
    x = 0x21 * x + string_to_hash[i];
  return x;
}
```

after changing the `string_to_hash` var type to char *, the code becomes quite easy to read. This C code translates into the following Python code:
```
def hash(string):
    c = 0x21
    x = 0x1505
    for i in string:
        x = (c * x) + ord(i)
    return x

h = hash("guy")
print "your hash is: " + hex(h)
```

Let's verify that the hash works, by analyzing the `eax` register when it is compared against the hash `0xD386D209`.

```
gdb-peda$ b *0x401753
gdb-peda$ r
``` 

on the clinet side
```
$	nc 127.0.0.1 12012
Welcome to FTP server
user blankwall
Please send password for user blankwall
pass guy
```

and once we hit the breakpoint:
```
Thread 2.1 "ftp_0319deb1c1c" hit Breakpoint 1, 0x0000000000401753 in ?? ()
gdb-peda$ p/x $eax
$1 = 0x7c978be4
```

Now let's see what hash our python code comes up with:

```
$	python hash.py 
your hash is: 0xb88789a
```

So as you can see, our hashing algorithm is not correct. Let's take a look at the assembly code, since IDA could of made a mistake. 

```
push    rbp
mov     rbp, rsp
mov     [rbp+hash], rdi
mov     [rbp+x], 1505h
mov     [rbp+i], 0
jmp     short for_loop
```

Here we see that the variable `x` is set equal to 0x150 (3360), and that the variable `i` is set equal to 0. In addition to that, we see the rdi register is loaded into the `hash` variable, which is probably the string being hashed. Then it jumps `for_loop`:

```
for_loop:
mov     eax, [rbp+i]
movsxd  rdx, eax
mov     rax, [rbp+hash]
add     rax, rdx
movzx   eax, byte ptr [rax]
test    al, al
jnz     short assembly_hash_block
```

Here we can see that it is essentially the comparison part of the for loop, where it checks if the `i` variable is equal to the number of characters in the `hash` variable, to see if it is done hashing the string.

```
assembly_hash_block:
mov     eax, [rbp+x]
shl     eax, 5
mov     edx, eax
mov     eax, [rbp+x]
lea     ecx, [rdx+rax]
mov     eax, [rbp+i]
movsxd  rdx, eax
mov     rax, [rbp+hash]
add     rax, rdx
movzx   eax, byte ptr [rax]
movsx   eax, al
add     eax, ecx
mov     [rbp+x], eax
add     [rbp+i], 1
```

This is the portion that actually does the hashing. We can see there is more going on then what the reversed C code told us. We can see that there is a binary shift, and that the variables are added in a different order. This assembly code translates into the following python code:

```
def hash(string):
    beg_x = 0x1505
    x = beg_x << 5
    x = x + beg_x
    for i in string:
            x = x + ord(i)
            beg_x = x
            x = x << 5
            x = x + beg_x
    return x

h = hash("guy")
print "your hash is: " + hex(h)
```

Here is how I belive the python code mataches the assembly (not %100 sure all of this is correct):

beg_x = 0x1505, beg_x = x
```
mov     [rbp+x], 1505h 

mov     eax, [rbp+x] (first)
```

x = beg_x << 5, x = x << 5
```
shl     eax, 5
mov     edx, eax
```

x = x + beg_x
```
mov     edx, eax

add     rax, rdx
```

x = x + ord(i)
```
mov     eax, [rbp+x] (second)
lea     ecx, [rdx+rax]
mov     eax, [rbp+i]
movsxd  rdx, eax
mov     rax, [rbp+hash]

movzx   eax, byte ptr [rax]
movsx   eax, al
add     eax, ecx

mov     [rbp+x], eax
```

When we run this script, we see that we still don't have the hashing algorithm down 100%. However if we look at the difference, we see that it isn't by much

```
$	python hash.py 
your hash is: 0x17c978bda
$	python
Python 2.7.13 (default, Jan 19 2017, 14:48:08) 
[GCC 6.3.0 20170118] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7c978be4 - 0x7c978bda
10
```

So with the exception of the `1` in front of out hash which we can just remove by only taking the last 8 characters, and that the hash we genertated is 10 less than the hash we should have (which we can just add on), the hash we generated is correct. Let's add in these changes:

```
def hash(string):
    beg_x = 0x1505
    x = beg_x << 5
    x = x + beg_x
    for i in string:
            x = x + ord(i)
            beg_x = x
            x = x << 5
            x = x + beg_x
    x = x + 10
    x = hex(x)[-8:]
    return x
    

h = hash("purple")
print "your hash is: 0x" + h

```

When we try it, we see that we are able to successfully gennerate the hash (just to make sure I tried a couple of different strings).  Now that we have the correct hashing algorithm, and the hash we are supposed to get, we can brute force different inputs untill we find an input that matches the hash. We can do this using a python library named `itertools`, which helps with looping. To start off with, we will try brute forcing up to ten characters, and only use lower case letters.

```
import itertools

thash = "0xd386d209"

characters = list("qwertyuioplkjhgfdsazxcvbnm")

def hash(string):
    beg_x = 0x1505
    x = beg_x << 5
    x = x + beg_x
    for i in string:
            x = x + ord(i)
            beg_x = x
            x = x << 5
            x = x + beg_x
    x = x + 10
    x = "0x" + hex(x)[-8:]
    return x

for c in range(1, 10):
    print "Cracking hash with length: " + str(c)
    for i in itertools.product(characters, repeat = c):
        ghash = hash(i)    
        if (ghash == thash):
            print "hash cracked: " + "".join(i)
            break
```

when we run the script:
```
$	python solve.py 
Cracking hash with length: 1
Cracking hash with length: 2
Cracking hash with length: 3
Cracking hash with length: 4
Cracking hash with length: 5
Cracking hash with length: 6

hash cracked: cookie
Cracking hash with length: 7
```

So we were able to crack the has, so the password is `cookie`. Let's try it:
```
$	nc 127.0.0.1 12012
Welcome to FTP server
user blankwall
Please send password for user blankwall
pass cookie
logged in
```

So we were able to log in. Now we just need to find the flag. When we look in IDA strings, we see an interesting string:

```
.rodata:0000000000403470 00000032 C Error reading RE flag please contact an organizer
```

When we look to see where the string is called, we see that i is called in function sub_4025F8. We see that that function is called when the command `RDF` is used, which isn't a command included in the help command. Let's try it:

```
$	nc 127.0.0.1 12012
Welcome to FTP server
user blankwall
Please send password for user blankwall
pass cookie
logged in
RDF
flag{n0_c0ok1e_ju$t_a_f1ag_f0r_you}
```

Just like that, we solved the challenge, thanks to the the writeup I mentioned at the beginning I used to make this.