# funmail 2

Let's take a look at the elf:

```
$	file funmail2.0 
funmail2.0: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1f665e0c6a35cc43b1963a0d9e9dc9645da8d81e, not stripped
$	./funmail2.0 
-------------------------------------------------------------------------------------------------------------------------------------------------
|   #     #                                                                                                                            		|
|   #  #  #  ######  #        ####    ####   #    #  ######      #####   ####       ######  #    #  #    #  #    #    ##    #  #       		|
|   #  #  #  #       #       #    #  #    #  ##  ##  #             #    #    #      #       #    #  ##   #  ##  ##   #  #   #  #       		|
|   #  #  #  #####   #       #       #    #  # ## #  #####         #    #    #      #####   #    #  # #  #  # ## #  #    #  #  #       2.0	|
|   #  #  #  #       #       #       #    #  #    #  #             #    #    #      #       #    #  #  # #  #    #  ######  #  #       		|
|   #  #  #  #       #       #    #  #    #  #    #  #             #    #    #      #       #    #  #   ##  #    #  #    #  #  #       		|
|    ## ##   ######  ######   ####    ####   #    #  ######        #     ####       #        ####   #    #  #    #  #    #  #  ######		|
-------------------------------------------------------------------------------------------------------------------------------------------------
	--Please login--
Username: root
*We have no users with the username: 'root'
	--Please login--
Username: ^C
```

So it is a 32 bit elf, that when we run it, it prompts us for a username and probably a password. Let's take a look at the main function:

```
  strcpy(jgalt, "john galt");
  printWelcome();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("\t--Please login--");
      printf("Username: ");
      if ( getLine(&username_input, 64) )
      {
        puts("Input is too long");
        return 1;
      }
      if ( !strcmp(&username_input, jgalt) )
        break;
      printf("*We have no users with the username: '%s'\n", &username_input);
    }
    printf("Password: ");
    if ( getLine(&password_input, 64) )
    {
      puts("Input is too long");
      return 1;
    }
    if ( !strcmp(&password_input, password) )
      break;
    puts("*Incorrect password");
  }
  printf("\tWelcome %s!\n", &username_input);
  puts(&s);
  puts("ERROR! Program failed to load emails.\nTerminating");
  puts(&v7);
  return 0;
}
```

So we can see here that the correct username is `john galt` and that the correct password is `more-secure-password` (double click on `password` to see it's value). However successfully authenticating doesn't do anything for us. When we look at the list of functions, we can see that it has `printFlag`. Let's try jumping to it in gdb:

```
gdb-peda$ b *main
Breakpoint 1 at 0xb24
gdb-peda$ r
Starting program: /Hackery/tuctf/funmail2/funmail2.0 

[----------------------------------registers-----------------------------------]
EAX: 0xf7fafdbc --> 0xffffd1cc --> 0xffffd395 ("CLUTTER_IM_MODULE=xim")
EBX: 0x0 
ECX: 0x7f2b0de4 
EDX: 0xffffd154 --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b5db0 
EBP: 0x0 
ESP: 0xffffd12c --> 0xf7e10276 (<__libc_start_main+246>:	add    esp,0x10)
EIP: 0x56555b24 (<main>:	lea    ecx,[esp+0x4])
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555b1f <showEmails+243>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x56555b22 <showEmails+246>:	leave  
   0x56555b23 <showEmails+247>:	ret    
=> 0x56555b24 <main>:	lea    ecx,[esp+0x4]
   0x56555b28 <main+4>:	and    esp,0xfffffff0
   0x56555b2b <main+7>:	push   DWORD PTR [ecx-0x4]
   0x56555b2e <main+10>:	push   ebp
   0x56555b2f <main+11>:	mov    ebp,esp
[------------------------------------stack-------------------------------------]
0000| 0xffffd12c --> 0xf7e10276 (<__libc_start_main+246>:	add    esp,0x10)
0004| 0xffffd130 --> 0x1 
0008| 0xffffd134 --> 0xffffd1c4 --> 0xffffd372 ("/Hackery/tuctf/funmail2/funmail2.0")
0012| 0xffffd138 --> 0xffffd1cc --> 0xffffd395 ("CLUTTER_IM_MODULE=xim")
0016| 0xffffd13c --> 0x0 
0020| 0xffffd140 --> 0x0 
0024| 0xffffd144 --> 0x0 
0028| 0xffffd148 --> 0xf7fae000 --> 0x1b5db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x56555b24 in main ()
gdb-peda$ j *printFlag
Continuing at 0x56555785.
TUCTF{l0c4l_<_r3m073_3x3cu710n}
[Inferior 1 (process 20452) exited normally]
Warning: not running or target is remote
```

Just like that, we captured the flag!
