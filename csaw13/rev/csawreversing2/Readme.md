# csawreversing2

Let's take a look at the binary:

```
$	file csaw2013reversing2.exe 
csaw2013reversing2.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So we can see that it is a 32 bit windows executable. When we try to run it, it appears to crash. let's look at the main function with ida:

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  HANDLE heap; // edi@1
  void *enc_transfer_heap; // esi@1
  char *v5; // eax@2
  char v4; // dl@3
  unsigned int i; // ecx@4
  unsigned int length; // eax@4

  heap = HeapCreate(0x40000u, 0, 0);
  enc_transfer_heap = HeapAlloc(heap, 8u, 0x25u);
  memcpy_s(enc_transfer_heap, 0x24u, &enc, 0x24u);
  if ( !*(_BYTE *)(*(_DWORD *)(__readfsdword(24) + 48) + 2) )
  {
    __debugbreak();
    v5 = (char *)enc_transfer_heap + 1;
    do
      v4 = *v5++;
    while ( v4 );
    i = 0;
    length = ((unsigned int)(v5 - ((_BYTE *)enc_transfer_heap + 2)) >> 2) + 1;
    if ( length > 0 )
    {
      do
        *((_DWORD *)enc_transfer_heap + i++) ^= 0x8899AABB;
      while ( i < length );
    }
  }
  MessageBoxA(0, (LPCSTR)enc_transfer_heap, "Flag", 2u);
  HeapFree(heap, 0, enc_transfer_heap);
  HeapDestroy(heap);
  ExitProcess(0);
}
```

So looking at this, it appears to be similar to the previous problem. It has a list of various one byte hex strings stored in `enc` that the program ends by printing, however before there is an if then statement, which if it passes then the hex strings are xored in groups of four by `0x8899aabb`.

Looking at `enc` we see the following hex strings:

```
.data:003D9B10 enc             db 0BBh ; +             ; DATA XREF: _main+21o
.data:003D9B11                 db 0CCh ; ¦
.data:003D9B12                 db 0F5h ; )
.data:003D9B13                 db 0E9h ; T
.data:003D9B14                 db 0DCh ; _
.data:003D9B15                 db 0D1h ; -
.data:003D9B16                 db 0F7h ; ˜
.data:003D9B17                 db 0FDh ; ²
.data:003D9B18                 db 0D6h ; +
.data:003D9B19                 db 0C8h ; +
.data:003D9B1A                 db 0FCh ; n
.data:003D9B1B                 db 0FAh ; ·
.data:003D9B1C                 db  89h ; ë
.data:003D9B1D                 db 0C3h ; +
.data:003D9B1E                 db 0EAh ; O
.data:003D9B1F                 db 0E9h ; T
.data:003D9B20                 db 0D7h ; +
.data:003D9B21                 db 0C3h ; +
.data:003D9B22                 db 0EDh ; f
.data:003D9B23                 db 0FCh ; n
.data:003D9B24                 db 0D7h ; +
.data:003D9B25                 db 0CFh ; -
.data:003D9B26                 db 0FBh ; v
.data:003D9B27                 db 0E1h ; ß
.data:003D9B28                 db 0CFh ; -
.data:003D9B29                 db 0C2h ; -
.data:003D9B2A                 db 0F8h ; °
.data:003D9B2B                 db 0FAh ; ·
.data:003D9B2C                 db 0DFh ; ¯
.data:003D9B2D                 db 0CFh ; -
.data:003D9B2E                 db 0EBh ; d
.data:003D9B2F                 db 0B2h ; ¦
.data:003D9B30                 db 0CBh ; -
.data:003D9B31                 db 0D7h ; +
.data:003D9B32                 db  99h ; Ö
.data:003D9B33                 db  88h ; ê
.data:003D9B34                 db 0BBh ; +
.data:003D9B35                 db 0AAh ; ¬
.data:003D9B36                 db  99h ; Ö
.data:003D9B37                 db  88h ; ê
```

So that is definately not the cleartext for the flag. So what probably happens is if that if then statement passes and the xor goes through, the result of that will be the flag (like how I manually decrypted the last challenge by hand). We could just change the values so the if then statement passes, however I just replicated it with a python script.

With this script, you will notice that the key (4 byte hex string used for xoring) is backwards, because of least endian (programs that read data by the least significant bit first). In addition to that, some the one byte hex strings were removed from the end, since they weren't a part of the flag:

```
#Establish an array of the encrypted flag one byte hex strings
enc = [ 0xbb, 0xcc, 0xf5, 0xe9, 0xdc, 0xd1, 0xf7, 0xfd, 0xd6, 0xc8, 0xfc, 0xfa, 0x89, 0xc3, 0xea, 0xe9, 0xd7, 0xc3, 0xed, 0xfc, 0xd7, 0xcf, 0xfb, 0xe1, 0xcf, 0xc2, 0xf8, 0xfa, 0xdf, 0xcf, 0xeb, 0xb2, 0xcb, 0xd7]

#Establish the array of hex strings which will be xoring
key = [ 0xbb, 0xaa, 0x99, 0x88]

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

and when we run the script:

```
$	python solve.py 
flag{number2isalittlebitharder:p}
```

Just like that, we captured the flag!
