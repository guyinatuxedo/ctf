# Csaw Quals 2017 TablEZ

This is an easy `100` point reversing problem from Csaw Quals 2017.

Let's take a look at the elf:
```
$	file tablez 
tablez: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=72adea86090fb7deeb319e95681fd2c669dcc503, not stripped
$	./tablez 
Please enter the flag:
flag{g0ttem}
WRONG
```

So we can see that this is a 64 bit elf. When we run it, it looks like it just scans in input, checks it, then tells us if it is right or wrong. Let's take a look at the code for the main function in IDA:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@5
  __int64 v4; // rsi@9
  size_t i; // [sp+0h] [bp-D0h]@1
  size_t inpLen; // [sp+8h] [bp-C8h]@1
  char encFlag[8]; // [sp+10h] [bp-C0h]@1
  char input[136]; // [sp+40h] [bp-90h]@1
  __int64 v9; // [sp+C8h] [bp-8h]@1

  v9 = *MK_FP(__FS__, 40LL);
  strcpy(encFlag, "'¦s¥)\x11t¦¦+Ö¦··(0\x1BqÖs#eÖ¦e\x11\x11+#Ö'·#Ö\x05e+");
  puts("Please enter the flag:");
  fgets(input, 128, stdin);
  input[strlen(input) - 1] = 0;
  inpLen = strlen(input);
  for ( i = 0LL; i < inpLen; ++i )
    input[i] = get_tbl_entry(input[i]);
  if ( inpLen == 0x25 )
  {
    if ( !strncmp(input, encFlag, 0x26uLL) )
    {
      puts("CORRECT <3");
      result = 0;
    }
    else
    {
      puts("WRONG");
      result = 1;
    }
  }
  else
  {
    puts("WRONG");
    result = 1;
  }
  v4 = *MK_FP(__FS__, 40LL) ^ v9;
  return result;
}
```

So we can see a couple of things from here. First that it scans in 128 bytes of data for our input. We can also see that the length of our input has to be `0x25` (37) bytes long, otherwise it just tells us we're wrong. On top of that we can that the string that we have to get our input equal to is `'¦s¥)\x11t¦¦+Ö¦··(0\x1BqÖs#eÖ¦e\x11\x11+#Ö'·#Ö\x05e+` (which in hex converts to `0x27b3739df511e7b1b3be99b3f9f9f4301b7199732365991b651111be239927f923990565ce`, which later on will be much easier to deal with in that form), however just the first 37 bytes. On top of that, we can see that each character of our input is ran through `get_tbl_entry()`, which when we look at it, we can see that it is essentially a lookup table that just swaps certain characters for other characters. Let's take a look at that function:

```
__int64 __fastcall get_tbl_entry(char a1)
{
  unsigned __int64 i; // [sp+Ch] [bp-8h]@1

  for ( i = 0LL; i <= 0xFE; ++i )
  {
    if ( a1 == *(&inpChar + 2 * i) )
      return outChar[2 * i];
  }
  return 0LL;
}
```
A couple of things, `inpChar` is at `0x201280` and `outChar` is one byte ahead at `0x201281`. Essentially what this does is it iterates through every other value in `out_char` starting at `0x1`. Once it finds the character that it got as an argument in `a1`, it will return the hex character proceeding it. So essentially, what we have to do look at the hex characters that is looking for, look and see what character comes before it. That way when we input that character, we will get the corresponding correct character we are looking for. 

A couple of things, from what I've seen there are multiple entries for each hex character entry. The easiest way I found to pick which one I go with, is just to see which preceeding character is within the ascii range, and make sure that that instance of the ascii character is the first instance of that character. You could just script out this process, or you could also just do trail and error and see what it maps which characters to.

Also here are all of the hex character stored in `outChar`:
```
.data:0000000000201281                 ; DATA XREF: get_tbl_entry+33o
.data:0000000000201281                 db 8, 45h, 9, 33h, 0Ah, 0B8h, 0Bh, 0D5h, 0Ch, 6, 0Dh, 0Ah
.data:0000000000201281                 db 0Eh, 0BCh, 0Fh, 0FAh, 10h, 79h, 11h, 24h, 12h, 0E1h
.data:0000000000201281                 db 13h, 0B2h, 14h, 0BFh, 15h, 2Ch, 16h, 0ADh, 17h, 86h
.data:0000000000201281                 db 18h, 60h, 19h, 0A4h, 1Ah, 0B6h, 1Bh, 0D8h, 1Ch, 59h
.data:0000000000201281                 db 1Dh, 87h, 1Eh, 41h, 1Fh, 94h, 20h, 77h, 21h, 0F0h, 22h
.data:0000000000201281                 db 4Fh, 23h, 0CBh, 24h, 61h, 2 dup(25h), 26h, 0C0h, 27h
.data:0000000000201281                 db 97h, 28h, 2Ah, 29h, 5Ch, 2Ah, 8, 2Bh, 0C9h, 2Ch, 9Fh
.data:0000000000201281                 db 2Dh, 43h, 2Eh, 4Eh, 2Fh, 0CFh, 30h, 0F9h, 31h, 3Eh
.data:0000000000201281                 db 32h, 6Fh, 33h, 65h, 34h, 0E7h, 35h, 0C5h, 36h, 39h
.data:0000000000201281                 db 37h, 0B7h, 38h, 0EFh, 39h, 0D0h, 3Ah, 0C8h, 3Bh, 2Fh
.data:0000000000201281                 db 3Ch, 0AAh, 3Dh, 0C7h, 3Eh, 47h, 3Fh, 3Ch, 40h, 81h
.data:0000000000201281                 db 41h, 32h, 42h, 49h, 43h, 0D3h, 44h, 0A6h, 45h, 96h
.data:0000000000201281                 db 46h, 2Bh, 47h, 58h, 48h, 40h, 49h, 0F1h, 4Ah, 9Ch, 4Bh
.data:0000000000201281                 db 0EEh, 4Ch, 1Ah, 4Dh, 5Bh, 4Eh, 0C6h, 4Fh, 0D6h, 50h
.data:0000000000201281                 db 80h, 51h, 2Dh, 52h, 6Dh, 53h, 9Ah, 54h, 3Dh, 55h, 0A7h
.data:0000000000201281                 db 56h, 93h, 57h, 84h, 58h, 0E0h, 59h, 12h, 5Ah, 3Bh, 5Bh
.data:0000000000201281                 db 0B9h, 5Ch, 9, 5Dh, 69h, 5Eh, 0BAh, 5Fh, 99h, 60h, 48h
.data:0000000000201281                 db 61h, 73h, 62h, 0B1h, 63h, 7Ch, 64h, 82h, 65h, 0BEh
.data:0000000000201281                 db 66h, 27h, 67h, 9Dh, 68h, 0FBh, 69h, 67h, 6Ah, 7Eh, 6Bh
.data:0000000000201281                 db 0F4h, 6Ch, 0B3h, 6Dh, 5, 6Eh, 0C2h, 6Fh, 5Fh, 70h, 1Bh
.data:0000000000201281                 db 71h, 54h, 72h, 23h, 73h, 71h, 74h, 11h, 75h, 30h, 76h
.data:0000000000201281                 db 0D2h, 77h, 0A5h, 78h, 68h, 79h, 9Eh, 7Ah, 3Fh, 7Bh
.data:0000000000201281                 db 0F5h, 7Ch, 7Ah, 7Dh, 0CEh, 7Eh, 0Bh, 7Fh, 0Ch, 80h
.data:0000000000201281                 db 85h, 81h, 0DEh, 82h, 63h, 83h, 5Eh, 84h, 8Eh, 85h, 0BDh
.data:0000000000201281                 db 86h, 0FEh, 87h, 6Ah, 88h, 0DAh, 89h, 26h, 8Ah, 88h
.data:0000000000201281                 db 8Bh, 0E8h, 8Ch, 0ACh, 8Dh, 3, 8Eh, 62h, 8Fh, 0A8h, 90h
.data:0000000000201281                 db 0F6h, 91h, 0F7h, 92h, 75h, 93h, 6Bh, 94h, 0C3h, 95h
.data:0000000000201281                 db 46h, 96h, 51h, 97h, 0E6h, 98h, 8Fh, 99h, 28h, 9Ah, 76h
.data:0000000000201281                 db 9Bh, 5Ah, 9Ch, 91h, 9Dh, 0ECh, 9Eh, 1Fh, 9Fh, 44h, 0A0h
.data:0000000000201281                 db 52h, 0A1h, 1, 0A2h, 0FCh, 0A3h, 8Bh, 0A4h, 3Ah, 0A5h
.data:0000000000201281                 db 0A1h, 0A6h, 0A3h, 0A7h, 16h, 0A8h, 10h, 0A9h, 14h, 0AAh
.data:0000000000201281                 db 50h, 0ABh, 0CAh, 0ACh, 95h, 0ADh, 92h, 0AEh, 4Bh, 0AFh
.data:0000000000201281                 db 35h, 0B0h, 0Eh, 0B1h, 0B5h, 0B2h, 20h, 0B3h, 1Dh, 0B4h
.data:0000000000201281                 db 5Dh, 0B5h, 0C1h, 0B6h, 0E2h, 0B7h, 6Eh, 0B8h, 0Fh, 0B9h
.data:0000000000201281                 db 0EDh, 0BAh, 90h, 0BBh, 0D4h, 0BCh, 0D9h, 0BDh, 42h
.data:0000000000201281                 db 0BEh, 0DDh, 0BFh, 98h, 0C0h, 57h, 0C1h, 37h, 0C2h, 19h
.data:0000000000201281                 db 0C3h, 78h, 0C4h, 56h, 0C5h, 0AFh, 0C6h, 74h, 0C7h, 0D1h
.data:0000000000201281                 db 0C8h, 4, 0C9h, 29h, 0CAh, 55h, 0CBh, 0E5h, 0CCh, 4Ch
.data:0000000000201281                 db 0CDh, 0A0h, 0CEh, 0F2h, 0CFh, 89h, 0D0h, 0DBh, 0D1h
.data:0000000000201281                 db 0E4h, 0D2h, 38h, 0D3h, 83h, 0D4h, 0EAh, 0D5h, 17h, 0D6h
.data:0000000000201281                 db 7, 0D7h, 0DCh, 0D8h, 8Ch, 0D9h, 8Ah, 0DAh, 0B4h, 0DBh
.data:0000000000201281                 db 7Bh, 0DCh, 0E9h, 0DDh, 0FFh, 0DEh, 0EBh, 0DFh, 15h
.data:0000000000201281                 db 0E0h, 0Dh, 0E1h, 2, 0E2h, 0A2h, 0E3h, 0F3h, 0E4h, 34h
.data:0000000000201281                 db 0E5h, 0CCh, 0E6h, 18h, 0E7h, 0F8h, 0E8h, 13h, 0E9h
.data:0000000000201281                 db 8Dh, 0EAh, 7Fh, 0EBh, 0AEh, 0ECh, 21h, 0EDh, 0E3h, 0EEh
.data:0000000000201281                 db 0CDh, 0EFh, 4Dh, 0F0h, 70h, 0F1h, 53h, 0F2h, 0FDh, 0F3h
.data:0000000000201281                 db 0ABh, 0F4h, 72h, 0F5h, 64h, 0F6h, 1Ch, 0F7h, 66h, 0F8h
.data:0000000000201281                 db 0A9h, 0F9h, 0B0h, 0FAh, 1Eh, 0FBh, 0D7h, 0FCh, 0DFh
.data:0000000000201281                 db 0FDh, 36h, 0FEh, 7Dh, 0FFh
.data:000000000020147D                 db  31h ; 1
.data:000000000020147D _data           ends
```

After a couple of minutes of work, we map out the flag:

```
0x27:	0x66	f	
0xb3:	0x6c	l
0x73:	0x61	a
0x9d:	0x67	g
0xf5:	0x7b	{
0x11:	0x74	t
0xe7:	0x34	4
0xb1:	0x62	b
0xb3:	0x6c	l
0xbe:	0x65	e
0x99:	0xf5    _
0xb3:	0x6c	l
0xf9:	0x30	0
0xf9:	0x30	0
0xf4:	0x6b	k
0x30:	0x75	u
0x1b:	0x70	p
0x71:	0x73	s
0x99:	0x5f    _
0x73:	0x61	a
0x23:	0x72    r
0x65:	0x33    3
0x99:	0x5f    _
0x1b:	0x32    b
0x65:	0x33    3
0x11:	0x74    t
0x11:	0x74    t
0xbe:	0x65    e
0x23:	0x72    r
0x99:	0x5f    _
0x27:	0x66    f 
0xf9:	0x30    0
0x23:	0x72    r
0x99:	0x5f    _
0x05:	0x6d    m
0x65:	0x33    3
0xce:	0x7d    }
```

and when we try the flag `flag{t4ble_l00kups_ar3_b3tter_f0r_m3}`:

```
$	./tablez 
Please enter the flag:
flag{t4ble_l00kups_ar3_b3tter_f0r_m3}
CORRECT <3
```

Just like that, we captured the flag.
