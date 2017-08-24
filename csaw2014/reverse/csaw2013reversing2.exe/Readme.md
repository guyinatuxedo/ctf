# csaw2013reversing2.exe

Let's take a look at the binary:

```
$	file csaw2013reversing2.exe 
csaw2013reversing2.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So we can see it is a 32 bit windows executable. When we run it, we see a messagebox with some unicode characters on it. Let's take a look at the main function in IDA:

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx@1
  LPVOID lpMem; // [sp+8h] [bp-Ch]@1
  HANDLE hHeap; // [sp+10h] [bp-4h]@1

  hHeap = HeapCreate(0x40000u, 0, 0);
  lpMem = HeapAlloc(hHeap, 8u, MaxCount + 1);
  memcpy_s(lpMem, MaxCount, &enc, MaxCount);
  if ( sub_40102A() || IsDebuggerPresent() )
  {
    __debugbreak();
    decrypt_func(v3 + 4, (int)lpMem);
    ExitProcess(0xFFFFFFFF);
  }
  MessageBoxA(0, (LPCSTR)lpMem + 1, "Flag", 2u);
  HeapFree(hHeap, 0, lpMem);
  HeapDestroy(hHeap);
  ExitProcess(0);
}
```

So this looks pretty similar to the other two `csaw2013` reversing challenges. What is probably going on is the flag is encrypted and stored in `enc`. An if then statement occurs, and if it executes the flag is decrypted with `decrypt_func`. After that it displays the contents of flag, whether or not it is still encrypted, in a messagebox. Let's take a look at the `decrypt_func`:

```
unsigned int __fastcall decrypt_func(int a1, int a2)
{
  int key_transfer; // esi@1
  char *v3; // eax@1
  char v4; // cl@2
  unsigned int i; // ecx@3
  unsigned int flag_length; // eax@3

  key_transfer = key;
  v3 = (char *)(a2 + 1);
  do
    v4 = *v3++;
  while ( v4 );
  i = 0;
  flag_length = ((unsigned int)&v3[-a2 - 2] >> 2) + 1;
  if ( flag_length )
  {
    do
      *(_DWORD *)(a2 + 4 * i++) ^= key_transfer;
    while ( i < flag_length );
  }
  return flag_length;
}
```

This again looks like the previous two `csaw2013` reversing challenges. We can see that four characters from the flag will be xored against they key at a time. Let's take a look at the encrypted flag, and the key being used:

key:
```
.data:00409B38 key             dd 0DDCCAABBh           ; DATA XREF: decrypt_func+1r
.data:00409B3C                 align 10h
```


enc:
```
.data:00409B10 enc             db 0BBh ; +             ; DATA XREF: _main+33o
.data:00409B11                 db 0CCh ; ¦
.data:00409B12                 db 0A0h ; á
.data:00409B13                 db 0BCh ; +
.data:00409B14                 db 0DCh ; _
.data:00409B15                 db 0D1h ; -
.data:00409B16                 db 0BEh ; +
.data:00409B17                 db 0B8h ; +
.data:00409B18                 db 0CDh ; -
.data:00409B19                 db 0CFh ; -
.data:00409B1A                 db 0BEh ; +
.data:00409B1B                 db 0AEh ; «
.data:00409B1C                 db 0D2h ; -
.data:00409B1D                 db 0C4h ; -
.data:00409B1E                 db 0ABh ; ½
.data:00409B1F                 db  82h ; é
.data:00409B20                 db 0D2h ; -
.data:00409B21                 db 0D9h ; +
.data:00409B22                 db  93h ; ô
.data:00409B23                 db 0B3h ; ¦
.data:00409B24                 db 0D4h ; +
.data:00409B25                 db 0DEh ; ¦
.data:00409B26                 db  93h ; ô
.data:00409B27                 db 0A9h ; ¬
.data:00409B28                 db 0D3h ; +
.data:00409B29                 db 0CBh ; -
.data:00409B2A                 db 0B8h ; +
.data:00409B2B                 db  82h ; é
.data:00409B2C                 db 0D3h ; +
.data:00409B2D                 db 0CBh ; -
.data:00409B2E                 db 0BEh ; +
.data:00409B2F                 db 0B9h ; ¦
.data:00409B30                 db  9Ah ; Ü
.data:00409B31                 db 0D7h ; +
.data:00409B32                 db 0CCh ; ¦
.data:00409B33                 db 0DDh ; ¦
```

So we can see that the encrypted flag `enc` contains a sequence of one byte hex strings, and that `key` contains a 4 byte hex string. With this, we can just code some python to do the decryption. If you would like more detail, please refer to the other `csaw2013reversing` writeups.

Also I should mention that another way (probably easier) to solve this is to either patch the binary to always pass the if then statement so it decrypts the flag for you, or just jump to it in a debugger, which can be referenced here: `https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/csaw2013reversing2.exe`

```
#Establish an array of the encrypted flag one byte hex strings
enc = [0xBB, 0xCC, 0xA0, 0xBC, 0xDC, 0xD1, 0xBE, 0xB8, 0xCD, 0xCF, 0xBE, 0xAE, 0xD2, 0xC4, 0xAB, 0x82, 0xD2, 0xD9, 0x93, 0xB3, 0xD4, 0xDE, 0x93, 0xA9, 0xD3, 0xCB, 0xB8, 0x82, 0xD3, 0xCB, 0xBE, 0xB9, 0x9A, 0xD7, 0xCC, 0xDD ]

#Establish the array of hex strings which will be xoring
key = [ 0xbb, 0xaa, 0xcc, 0xdd ]

#Establish the string which will store the decrypted flag
flag = ""

#Establish variables for iteration counting
i = 0
j = 0

#Establish the for loop which will do the xoring
for x in enc:
    flag += chr(enc[i] ^ key[j])
    i += 1
    j += 1
    #Reset the second iteration counter after four iterations
    if j > 3:
        j = 0

#Print the flag
print flag
```

As you can see, the code is recycled for `csaw2013reversing2`. Now let's run it!

```
$	python solve.py 
flag{reversing_is_not_that_hard!}
guyinatuxedo@tux:/Hackery/ancient/14csaw/reverse/csaw2013re
```

Just like that we captured the flag!
