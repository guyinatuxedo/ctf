# bo

Let's take a look at the binary:

```
$	file bo
bo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=698e3f2e1dd83dd1c963ea59cdad3d19aa738c8c, not stripped
```

So we can see that it is a 32 bit linux elf. Let's try running it:

```
$	./bo
Is
any
of
this
working
?
```

So from here it appears like nothing is happening, however it is probably running a fork server (based upon experience from other ctf problems). We can use netstat to see what port it is listening on with the server still running:

```
$	netstat -planet | grep bo
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:1515            0.0.0.0:*               LISTEN      1000       2624847    16039/./bo 
```

So here we can see it is listening on port `1515`. With the server still running, let's connect to it:

```
$	nc 127.0.0.1 1515
Welcome to CSAW CTF!
Time to break out IDA Demo and see what's going on inside me.  :]

Hello
anything happening?

```

So we see that when we connect to the sever all it appears to do is just print some text. Before we open it in IDA, let's run strings on the binary, which will pull out any human readable characters. This might give us a flag:

```
$	strings bo | grep flag
flag{exploitation_is_easy!}
```

Just like that, we got the flag!
