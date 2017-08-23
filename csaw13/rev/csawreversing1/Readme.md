# CsawReversing 1

Let's take a look at the binary:

```
$	file csaw2013reversing1.exe 
csaw2013reversing1.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So it is a 32 bit binary. When we run it, we get a textbox with a bunch of unicode characters. Let's take a look at the main function in IDA.

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int text_length; // kr00_4@3
  unsigned int i; // ecx@3

  if ( IsDebuggerPresent() )
  {
    text_length = strlen(Text);
    i = 0;
    if ( text_length >> 2 != -1 )
    {
      do
        *(_DWORD *)&Text[4 * i++] ^= 0xCCDDEEFF;
      while ( i < (text_length >> 2) + 1 );
    }
    MessageBoxA(0, Text, "Flag", 2u);
  }
  else
  {
    MessageBoxA(0, Text, "Flag", 2u);
  }
  ExitProcess(0);
}
```

Now looking at this code, we see that essentially it checks to see if a debugger is present, and if it is, it set's `Text` equal to itself xored by `0xccddeeff`. After that check, it just displays `Text` in a messagebox. When we look at Text, we can see the same Unicode characters that we got from the message box.

```
.data:00DF8B20 ; CHAR Text[]
.data:00DF8B20 Text            dd 0ABBC8299h           ; DATA XREF: _main+11o
.data:00DF8B20                                         ; _main+20o ...
.data:00DF8B24                 db  84h ; ä
.data:00DF8B25                 db  9Ah ; Ü
.data:00DF8B26                 db 0B5h
.data:00DF8B27                 db 0A5h ; Ñ
.data:00DF8B28                 db  8Ch ; î
.data:00DF8B29                 db 0DFh ; ¯
.data:00DF8B2A                 db 0B4h ; ¦
.data:00DF8B2B                 db 0BFh ; +
.data:00DF8B2C                 db  8Fh ; Å
.data:00DF8B2D                 db  9Ch ; £
.data:00DF8B2E                 db 0B8h ; +
.data:00DF8B2F                 db 0B8h ; +
.data:00DF8B30                 db  8Bh ; ï
.data:00DF8B31                 db  97h ; ù
.data:00DF8B32                 db 0B8h ; +
.data:00DF8B33                 db 0ADh ; ¡
.data:00DF8B34                 db  8Ch ; î
.data:00DF8B35                 db  97h ; ù
.data:00DF8B36                 db 0E7h ; t
.data:00DF8B37                 db 0E5h ; s
.data:00DF8B38                 db  82h ; é
.data:00DF8B39                 db 0EEh ; e
.data:00DF8B3A                 db 0DDh ; ¦
.data:00DF8B3B                 db 0CCh ; ¦
.data:00DF8B3C                 db 0FFh
.data:00DF8B3D                 db 0EEh ; e
.data:00DF8B3E                 db 0DDh ; ¦
.data:00DF8B3F                 db 0CCh ; ¦
```

So this text is probably the flag encrypted, and that function which runs if a debugger is present, will decrypt it. To check I just run it with the local Win32 debugger and I get the flag in the messagebox `flag{this1isprettyeasy:)}`. Incase you're curious on how exactly the decryption process works, I did solve it manually (may  not of noticed the `IsDebuggerPresent()` untill after I had the flag).

```
0x99 ^ 0xff = 0x66 = 'f'
0x82 ^ 0xee = 0x6c = 'l'
0xbc ^ 0xdd = 0x61 = 'a'
0xab ^ 0xcc = 0x67 = 'g'
0x84 ^ 0xff = 0x7b = '{'
0x9a ^ 0xee = 0x74 = 't'
0xb5 ^ 0xdd = 0x68 = 'h'
0xa5 ^ 0xcc = 0x69 = 'i'
0x8c ^ 0xff = 0x73 = 's'
0xdf ^ 0xee = 0x31 = '1'
0xb4 ^ 0xdd = 0x69 = 'i'
0xbf ^ 0xcc = 0x73 = 's'
0x8f ^ 0xff = 0x70 = 'p'
0x9c ^ 0xee = 0x72 = 'r'
0xb8 ^ 0xdd = 0x65 = 'e'
0xb8 ^ 0xcc = 0x74 = 't'
0x8b ^ 0xff = 0x74 = 't'
0x97 ^ 0xee = 0x79 = 'y'
0xb8 ^ 0xdd = 0x65 = 'e'
0xad ^ 0xcc = 0x61 = 'a'
0x8c ^ 0xff = 0x73 = 's'
0x97 ^ 0xee = 0x79 = 'y'
0xe7 ^ 0xdd = 0x3a = ':'
0xe5 ^ 0xcc = 0x29 = ')'
0x82 ^ 0xff = 0x7d = `}`
```
