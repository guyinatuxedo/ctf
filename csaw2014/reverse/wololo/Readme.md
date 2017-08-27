# wololo

This challenge was my first dealing with iOS ARM, and this writeup is based off of this writeup: `http://tasteless.eu/post/2014/09/csaw-2014-quals-wololo-rev300/`

Starting off, looking at the file they provided us with `wololo.lst.xy`, and can see that it is ARM assembly. When we make the network connection to the server that the challenge provided us with, we can see the following message (since when I went through this challenge was years after the comp and the server is down, this is coming from `https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/wololo`):

```
$ nc 54.164.98.39 2510

I'm ready to accept your input file!

Run this with: python wololo_x.py hostname port file_to_submit

#!/usr/bin/env python

import sys, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], int(sys.argv[2])))
print s.recv(1024)

contents = open(sys.argv[3], "rb").read()
s.send(struct.pack("<I", len(contents)) + contents)

print "The challenge server says: ", s.recv(1024)
```

So it appears to give us a python file, as a way of submitting our solution to this challenge, which should be a file. Durring the competition, if we were to submit a file that wasn't the correct solution, we would get this message (This also came from `https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/wololo`):

```
$ python wololo_x.py 54.164.98.39 2510 some-random-test-file
The challenge server says:  Sorry, your file did not pass all the checks.
```

So let's take a look at the assembly file they gave us. Taking a look through the assembly code reveals some interesting subroutines:


##### validate_database
```
__text:00000AF8 ; =============== S U B R O U T I N E =======================================
__text:00000AF8
__text:00000AF8
__text:00000AF8                 EXPORT _validate_database
__text:00000AF8 _validate_database
__text:00000AF8
__text:00000AF8 var_2C          = -0x2C
__text:00000AF8 var_28          = -0x28
__text:00000AF8 var_24          = -0x24
__text:00000AF8 var_20          = -0x20
__text:00000AF8 var_1C          = -0x1C
__text:00000AF8 var_18          = -0x18
__text:00000AF8 var_14          = -0x14
__text:00000AF8 var_10          = -0x10
__text:00000AF8 var_C           = -0xC
__text:00000AF8
__text:00000AF8                 PUSH            {R7,LR}
__text:00000AFA                 MOV             R7, SP
__text:00000AFC                 SUB             SP, SP, #0x24
__text:00000AFE                 MOVS            R2, #0xC
__text:00000B04                 STR             R0, [SP,#0x2C+var_10]
__text:00000B06                 STR             R1, [SP,#0x2C+var_14]
__text:00000B08                 LDR             R0, [SP,#0x2C+var_10]
__text:00000B0A                 STR             R0, [SP,#0x2C+var_18]
__text:00000B0C                 STR             R2, [SP,#0x2C+var_1C]
__text:00000B0E                 LDR             R0, [SP,#0x2C+var_14]
__text:00000B10                 LDR             R1, [SP,#0x2C+var_1C]
__text:00000B12                 CMP             R0, R1
__text:00000B14                 BCS             loc_B20
__text:00000B16                 MOVS            R0, #0
__text:00000B1C                 STR             R0, [SP,#0x2C+var_C]
__text:00000B1E                 B               loc_C2A
__text:00000B20 ; ---------------------------------------------------------------------------
```

##### col_size
```
__text:00000A80 ; =============== S U B R O U T I N E =======================================
__text:00000A80
__text:00000A80
__text:00000A80                 EXPORT _col_size
__text:00000A80 _col_size                               ; CODE XREF: _validate_database+DE^Yp
__text:00000A80                                         ; _check_login+48^Yp ...
__text:00000A80
__text:00000A80 var_C           = -0xC
__text:00000A80 var_8           = -8
__text:00000A80 var_4           = -4
__text:00000A80
__text:00000A80                 SUB             SP, SP, #0xC
__text:00000A82                 STR             R0, [SP,#0xC+var_8]
__text:00000A84                 LDRB            R0, [R0]
__text:00000A86                 CMP             R0, #7
__text:00000A88                 STR             R0, [SP,#0xC+var_C]
__text:00000A8A                 BHI             loc_AEA
__text:00000A8C                 LDR             R1, [SP,#0xC+var_C]
__text:00000A8E                 TBB.W           [PC,R1] ; switch 8 cases
__text:00000A8E ; ---------------------------------------------------------------------------
```

##### check_login
```
__text:00000C30 ; =============== S U B R O U T I N E =======================================
__text:00000C30
__text:00000C30
__text:00000C30                 EXPORT _check_login
__text:00000C30 _check_login
__text:00000C30
__text:00000C30 var_6C          = -0x6C
__text:00000C30 var_68          = -0x68
__text:00000C30 var_64          = -0x64
__text:00000C30 var_60          = -0x60
__text:00000C30 var_5C          = -0x5C
__text:00000C30 var_58          = -0x58
__text:00000C30 var_54          = -0x54
__text:00000C30 var_50          = -0x50
__text:00000C30 var_4C          = -0x4C
__text:00000C30 var_48          = -0x48
__text:00000C30 var_44          = -0x44
__text:00000C30 var_40          = -0x40
__text:00000C30 var_3C          = -0x3C
__text:00000C30 var_38          = -0x38
__text:00000C30 var_34          = -0x34
__text:00000C30 var_30          = -0x30
__text:00000C30 var_2C          = -0x2C
__text:00000C30 var_28          = -0x28
__text:00000C30 var_24          = -0x24
__text:00000C30 var_20          = -0x20
__text:00000C30 var_1C          = -0x1C
__text:00000C30 var_18          = -0x18
__text:00000C30 var_14          = -0x14
__text:00000C30 var_10          = -0x10
__text:00000C30 var_C           = -0xC
__text:00000C30
__text:00000C30                 PUSH            {R7,LR}
__text:00000C32                 MOV             R7, SP
__text:00000C34                 SUB             SP, SP, #0x64
```

Validate Database, Column Size, Check Login, all of these are major signs that we're dealing with a database here. To solve the challenge, we will probably have to pass the `check_login` and `validate_database` checks (since those are the checks we got). The first thing that goes into this file should be the header, which we believe is in the file because of the hint that was given:

```
typedef struct
{
        uint32_t magic;
        uint32_t version;
        uint16_t num_cols;
        uint16_t num_rows;
} header_t;
```

So we know that the header is 12 bytes (96 bits). There are four pieces that we will need to find, `magic` `version` `num_cols` and `num_rows`. From the three subroutines that we know exist, it seems like the checks for them would be in `validate_database` since we don't appear to be dealing with authentication yet or the size of columns.

Let's take a look at the first segment of code for `validate_database` after the initilization part:

```
__text:00000B20 ; ---------------------------------------------------------------------------
__text:00000B20
__text:00000B20 loc_B20                                 ; CODE XREF: _validate_database+1C^Xj
__text:00000B20                 MOV             R0, #0x4F4C4F57
__text:00000B28                 LDR             R1, [SP,#0x2C+var_18]
__text:00000B2A                 LDR             R1, [R1]
__text:00000B2C                 CMP             R1, R0
__text:00000B2E                 BEQ             loc_B3A
__text:00000B30                 MOVS            R0, #0
__text:00000B36                 STR             R0, [SP,#0x2C+var_C]
__text:00000B38                 B               loc_C2A
__text:00000B3A ; ---------------------------------------------------------------------------
```

Just looking through the rest of this function, it appears that `var_18` is the file, since it is loaded into a register at the start of most sections of this function. Looking at this section, we can see that the string `WOLO` (in hex and least-endian is `0x4f4c4f57`) is moved into the `R0` register. We can also see that `var_18` is loaded into the `R1` register, however it doesn't have an offset so it is probably dealing with the first thing in the file `magic`. It then compares the two registers, and if the two are equal it branches off to `loc_B3A` and continues with the function. If they aren't equal then it branches off to `loc_C2A` which when we look at it, it just ends the function. So we know that `magic` has to be set equal to the hex string `0x4f4c4f57`.

```
__text:00000B3A ; ---------------------------------------------------------------------------
__text:00000B3A
__text:00000B3A loc_B3A                                 ; CODE XREF: _validate_database+36^Xj
__text:00000B3A                 LDR             R0, [SP,#0x2C+var_18]
__text:00000B3C                 LDR             R0, [R0,#4]
__text:00000B3E                 CMP             R0, #1
__text:00000B40                 BEQ             loc_B4C
__text:00000B42                 MOVS            R0, #0
__text:00000B48                 STR             R0, [SP,#0x2C+var_C]
__text:00000B4A                 B               loc_C2A
__text:00000B4C ; ---------------------------------------------------------------------------
```

This time we see the file `var_18` loaded into the `R0` register, with an offset of 4 bytes, so we are dealing with `version`. We see that after it's loaded into `R0`, `R0` is then checked to see if it is equal to 0x1, and if it is the function continues. So we will have to set `version` equal to the hex string `0x00000001`.

```
__text:00000B4C ; ---------------------------------------------------------------------------
__text:00000B4C
__text:00000B4C loc_B4C                                 ; CODE XREF: _validate_database+48^Xj
__text:00000B4C                 LDR             R0, [SP,#0x2C+var_18]
__text:00000B4E                 LDRH            R0, [R0,#0xA]
__text:00000B50                 CMP             R0, #4
__text:00000B52                 BGE             loc_B5E
__text:00000B54                 MOVS            R0, #0
__text:00000B5A                 STR             R0, [SP,#0x2C+var_C]
__text:00000B5C                 B               loc_C2A
__text:00000B5E ; ---------------------------------------------------------------------------
```

So here we see the file being loaded into `R0` with an offset of 0xA, so we are dealing with `num_rows`. In here we see that it is compared against 0x4, and branches if `num_rows` is greater than or equal to 4, so `num_rows` must be at least 4.

```
__text:00000B5E ; ---------------------------------------------------------------------------
__text:00000B5E
__text:00000B5E loc_B5E                                 ; CODE XREF: _validate_database+5A^Xj
__text:00000B5E                 LDR             R0, [SP,#0x2C+var_18]
__text:00000B60                 LDRH            R0, [R0,#0xA]
__text:00000B62                 CMP.W           R0, #0x1000
__text:00000B66                 BLE             loc_B72
__text:00000B68                 MOVS            R0, #0
__text:00000B6E                 STR             R0, [SP,#0x2C+var_C]
__text:00000B70                 B               loc_C2A
__text:00000B72 ; ---------------------------------------------------------------------------
```

Looking at this section, we see that we are again dealing with `num_rows` since the offset is again 0xA. This section is similar to the previous, however instead of comparing it against 0x4, it compares it against 0x1000, and it checks to see if `num_rows` is less than or equal to 0x1000. So based upon the previous two sections `num_rows` has to be between 0x4-0x1000

```
__text:00000B72 ; ---------------------------------------------------------------------------
__text:00000B72
__text:00000B72 loc_B72                                 ; CODE XREF: _validate_database+6E^Xj
__text:00000B72                 LDR             R0, [SP,#0x2C+var_18]
__text:00000B74                 LDRH            R0, [R0,#8]
__text:00000B76                 CMP             R0, #4
__text:00000B78                 BGE             loc_B84
__text:00000B7A                 MOVS            R0, #0
__text:00000B80                 STR             R0, [SP,#0x2C+var_C]
__text:00000B82                 B               loc_C2A
__text:00000B84 ; ---------------------------------------------------------------------------
```

This time we are dealing with `num_cols`, since the offset now is 0x8. Like before, it is checking to see if it is greater than or equal to 0x4.

```
__text:00000B84 ; ---------------------------------------------------------------------------
__text:00000B84
__text:00000B84 loc_B84                                 ; CODE XREF: _validate_database+80^Xj
__text:00000B84                 LDR             R0, [SP,#0x2C+var_18]
__text:00000B86                 LDRH            R0, [R0,#8]
__text:00000B88                 CMP             R0, #0x10
__text:00000B8A                 BLE             loc_B96
__text:00000B8C                 MOVS            R0, #0
__text:00000B92                 STR             R0, [SP,#0x2C+var_C]
__text:00000B94                 B               loc_C2A
__text:00000B96 ; ---------------------------------------------------------------------------
```

Again we are dealing with `num_cols`, and this time it checks to see if it is less than or equal to 0x10.

Looking at the following sections, it appears like the switches from checking the header to doing other things, so we've probably covered the ehader check, With that we know that the header has to look like this (remember for this section we need our data to be in least endian in order for it to be read correctly):

```
magic:			4 byte hex string = 0x4F4C4F57	| "\x57\x4f\x4c\x4f"
version:		4 byte hex string = 0x00000001	| "\x01\x00\x00\x00"
num_rows:		2 byte hex string = 0x0004		| "\x04\x00" 
num_columns:	2 byte hex string = 0x0004		| "\x04\x00"
```

The reason why I set `num_rows` and `num_columns` equal to 0x4 will be later explained. Now that we have the header, we can go about making the actual database file. The next thing we need to find out is what columns we need, which will be dictated by the checks in `check_login`. 

```
__text:00000CCE loc_CCE                                 ; CODE XREF: _check_login+296^Yj
__text:00000CCE                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000CD0                 LDR             R1, [SP,#0x6C+var_18]
__text:00000CD2                 LDRH            R1, [R1,#8]
__text:00000CD4                 CMP             R0, R1
__text:00000CD6                 BCS.W           loc_EC8
__text:00000CDA                 MOV             R1, #(aUsername - 0xCE6) ; "USERNAME"
__text:00000CE2                 ADD             R1, PC  ; "USERNAME"
__text:00000CE4                 MOVS            R2, #8  ; size_t
__text:00000CEA                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000CEC                 LDR             R3, [SP,#0x6C+var_1C]
__text:00000CEE                 MOV             R9, #0x11
__text:00000CF6                 MUL.W           R0, R0, R9
__text:00000CFA                 ADD             R0, R3
__text:00000CFC                 ADDS            R0, #1  ; char *
__text:00000CFE                 BLX             _strncmp
__text:00000D02                 CMP             R0, #0
__text:00000D04                 BNE             loc_D3E
__text:00000D06                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000D08                 LDR             R1, [SP,#0x6C+var_1C]
__text:00000D0A                 MOVS            R2, #0x11
__text:00000D10                 MULS            R0, R2
__text:00000D12                 ADD             R0, R1
__text:00000D14                 LDRB            R0, [R0]
__text:00000D16                 CMP             R0, #5
__text:00000D18                 BNE             loc_D3E
__text:00000D1A                 MOV             R1, #(aCaptainfalcon - 0xD26) ; "captainfalcon"
__text:00000D22                 ADD             R1, PC  ; "captainfalcon"
__text:00000D24                 MOVS            R2, #0xE ; size_t
__text:00000D2A                 LDR             R0, [SP,#0x6C+var_38] ; char *
__text:00000D2C                 BLX             _strncmp
__text:00000D30                 CMP             R0, #0
__text:00000D32                 BNE             loc_D3C
__text:00000D34                 MOVS            R0, #1
__text:00000D3A                 STR             R0, [SP,#0x6C+var_3C]
__text:00000D3C
__text:00000D3C loc_D3C                                 ; CODE XREF: _check_login+102^Xj
__text:00000D3C                 B               loc_D3E
__text:00000D3E ; ---------------------------------------------------------------------------

```

Here we can see is the check for the username. Looking at it, we can see that is is pulling data from a coulumn named `USERNAME`.  The value it appears to be checking for is `captainfalcon`. In addition to that, the data type it expects is a 16 bit string, due to the use of `strncmp` and 0xE (hex for 14) being passed as an argument to it for amount of characters to read.

```
__text:00000D3E ; ---------------------------------------------------------------------------
__text:00000D3E
__text:00000D3E loc_D3E                                 ; CODE XREF: _check_login+D4^Xj
__text:00000D3E                                         ; _check_login+E8^Xj ...
__text:00000D3E                 MOV             R1, #(aPassword - 0xD4A) ; "PASSWORD"
__text:00000D46                 ADD             R1, PC  ; "PASSWORD"
__text:00000D48                 MOVS            R2, #8  ; size_t
__text:00000D4E                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000D50                 LDR             R3, [SP,#0x6C+var_1C]
__text:00000D52                 MOV             R9, #0x11
__text:00000D5A                 MUL.W           R0, R0, R9
__text:00000D5E                 ADD             R0, R3
__text:00000D60                 ADDS            R0, #1  ; char *
__text:00000D62                 BLX             _strncmp
__text:00000D66                 CMP             R0, #0
__text:00000D68                 BNE             loc_DA2
__text:00000D6A                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000D6C                 LDR             R1, [SP,#0x6C+var_1C]
__text:00000D6E                 MOVS            R2, #0x11
__text:00000D74                 MULS            R0, R2
__text:00000D76                 ADD             R0, R1
__text:00000D78                 LDRB            R0, [R0]
__text:00000D7A                 CMP             R0, #6
__text:00000D7C                 BNE             loc_DA2
__text:00000D7E                 MOV             R1, #(aFc03329505475d - 0xD8A) ; "fc03329505475dd4be51627cc7f0b1f1"
__text:00000D86                 ADD             R1, PC  ; "fc03329505475dd4be51627cc7f0b1f1"
__text:00000D88                 MOVS            R2, #0x20 ; ' ' ; size_t
__text:00000D8E                 LDR             R0, [SP,#0x6C+var_38] ; char *
__text:00000D90                 BLX             _strncmp
__text:00000D94                 CMP             R0, #0
__text:00000D96                 BNE             loc_DA0
__text:00000D98                 MOVS            R0, #1
__text:00000D9E                 STR             R0, [SP,#0x6C+var_40]
__text:00000DA0
__text:00000DA0 loc_DA0                                 ; CODE XREF: _check_login+166^Xj
__text:00000DA0                 B               loc_DA2
__text:00000DA2 ; ---------------------------------------------------------------------------
__text:00000DA2

```

The next column it checks for appears to be `PASSWORD`
. This time it appears to be looking for a 32 bit string, `fc03329505475dd4be51627cc7f0b1f1` due to the size of the string and the `strncmp` called used to evaluate it.

```
__text:00000DA2 ; ---------------------------------------------------------------------------
__text:00000DA2
__text:00000DA2 loc_DA2                                 ; CODE XREF: _check_login+138^Xj
__text:00000DA2                                         ; _check_login+14C^Xj ...
__text:00000DA2                 MOV             R1, #(aAdmin - 0xDAE) ; "ADMIN"
__text:00000DAA                 ADD             R1, PC  ; "ADMIN"
__text:00000DAC                 MOVS            R2, #5  ; size_t
__text:00000DB2                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000DB4                 LDR             R3, [SP,#0x6C+var_1C]
__text:00000DB6                 MOV             R9, #0x11
__text:00000DBE                 MUL.W           R0, R0, R9
__text:00000DC2                 ADD             R0, R3
__text:00000DC4                 ADDS            R0, #1  ; char *
__text:00000DC6                 BLX             _strncmp
__text:00000DCA                 CMP             R0, #0
__text:00000DCC                 BNE             loc_E0C
__text:00000DCE                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000DD0                 LDR             R1, [SP,#0x6C+var_1C]
__text:00000DD2                 MOVS            R2, #0x11
__text:00000DD8                 MULS            R0, R2
__text:00000DDA                 ADD             R0, R1
__text:00000DDC                 LDRB            R0, [R0]
__text:00000DDE                 CMP             R0, #0
__text:00000DE0                 BNE             loc_E0C
__text:00000DE2                 LDR             R0, [SP,#0x6C+var_38]
__text:00000DE4                 LDRB            R0, [R0]
__text:00000DE6                 STRB.W          R0, [SP,#0x6C+var_50]
__text:00000DEA                 LDRB.W          R0, [SP,#0x6C+var_50]
__text:00000DEE                 CMP             R0, #1
__text:00000DF0                 BNE             loc_DFA
__text:00000DF2                 MOVS            R0, #1
__text:00000DF8                 STR             R0, [SP,#0x6C+var_44]
```

The next column name we have is `ADMIN`. Unlike the previous two columns, this one appears to evaluate the data using `CMP` so it is expecting an integer. We can see that it is comparing it against 0, and branching only if it isn't equal. So we need to make a coulmn named `ADMIN` and set it equal to something other than `0`.

```
__text:00000E0C loc_E0C                                 ; CODE XREF: _check_login+19C^Xj
__text:00000E0C                                         ; _check_login+1B0^Xj
__text:00000E0C                 MOV             R1, #(aIsawesome - 0xE18) ; "ISAWESOME"
__text:00000E14                 ADD             R1, PC  ; "ISAWESOME"
__text:00000E16                 MOVS            R2, #9  ; size_t
__text:00000E1C                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000E1E                 LDR             R3, [SP,#0x6C+var_1C]
__text:00000E20                 MOV             R9, #0x11
__text:00000E28                 MUL.W           R0, R0, R9
__text:00000E2C                 ADD             R0, R3
__text:00000E2E                 ADDS            R0, #1  ; char *
__text:00000E30                 BLX             _strncmp
__text:00000E34                 CMP             R0, #0
__text:00000E36                 BNE             loc_E68
__text:00000E38                 LDR             R0, [SP,#0x6C+var_4C]
__text:00000E3A                 LDR             R1, [SP,#0x6C+var_1C]
__text:00000E3C                 MOVS            R2, #0x11
__text:00000E42                 MULS            R0, R2
__text:00000E44                 ADD             R0, R1
__text:00000E46                 LDRB            R0, [R0]
__text:00000E48                 CMP             R0, #0
__text:00000E4A                 BNE             loc_E68
__text:00000E4C                 LDR             R0, [SP,#0x6C+var_38]
__text:00000E4E                 LDRB            R0, [R0]
__text:00000E50                 STRB.W          R0, [SP,#0x6C+var_54]
__text:00000E54                 LDRB.W          R0, [SP,#0x6C+var_54]
__text:00000E58                 CMP             R0, #1
__text:00000E5A                 MOVW            R0, #0
__text:00000E5E                 IT EQ
__text:00000E60                 MOVEQ           R0, #1
__text:00000E62                 AND.W           R0, R0, #1
__text:00000E66                 STR             R0, [SP,#0x6C+var_48]
__text:00000E68
```

This section looks similar to the previous block, except the name is `ISAWESOME` instead of `ADMIN`. It performs the same check on the value it holds, which will pass if it isn't equal to zero. So we will need to create a coulmn and have the value stored in it equal to something other than `0`.

Looking on after that, it appears that there are no more checks in the `check_login` function. So we know what to name the columns, and values to store, and a hint tells us about the structure they should have:

```
typedef struct
{
        uint8_t type;
        char name[16];
} col_t;

/*
 * Column types:
 *   * 0 = 8bit integer
 *   * 1 = 16bit integer
 *   * 2 = 32bit integer
 *   * 3 = 64bit integer
 *   * 4 = 8byte string
 *   * 5 = 16byte string
 *   * 6 = 32byte string
 *   * 7 = unix timestamp encoded as a 32bit integer
 *
 */
```

So looking at that, we can see that a column shou ld be 17 bytes (one byte for the type, 16 for the name). As far as data types go, `USERNAME` should be 5, `PASSWORD` should be 6, and `ADMIN` and `ISAWESOME` should both be 0. That leaves us with the following columns:

```
USERNAME:	0x05 + 0x555345524e414d450000000000000000	|	"\x05" + "\x55\x53\x45\x52\x4e\x41\x4d\x45\x00\x00\x00\x00\x00\x00\x00\x00"
PASSWORD:	0x06 + 0x5041535357f452440000000000000000	|	"\x06" + "\x50\x41\x53\x53\x57\x4f\x52\x44\x00\x00\x00\x00\x00\x00\x00\x00"
ADMIN:		0x00 + 0x41444d494e0000000000000000000000	|	"\x00" + "\x41\x44\x4d\x49\x4e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ISAWESOME:	0x00 + 0x4953415745534f4d4500000000000000	|	"\x00" + "\x49\x53\x41\x57\x45\x53\x4f\x4d\x45\x00\x00\x00\x00\x00\x00\x00"
```

With that, there is only one piece left that we need. That is the rows, which will hold the data to pass `login_check`. We know what data to put in the rows, and we have already established what data types the 4 columns are, so we can just make it:

```
`USERNAME` + `PASSWORD` + `ADMIN` + `ISAWESOME`
0x6361707461696e66616c636f6e000000 + 0x6663303333323935303534373564643462653531363237636337663062316631 + 0x01 + 0x01
"\x63\x61\x70\x74\x61\x69\x6e\x66\x61\x6c\x63\x6f\x6e\x00\x00\x00" + "\x66\x63\x30\x33\x33\x32\x39\x35\x30\x35\x34\x37\x35\x64\x64\x34\x62\x65\x35\x31\x36\x32\37\x63\x63\x37\x66\x30\x62\x31\x66\x31" + "\x01" + "\x01"
```

Now since the requirement is for there to be at least 4 rows, we will just have that row 4 times. Now we can generate the file we need:

```
$	python -c 'print "\x57\x4f\x4c\x4f" + "\x01\x00\x00\x00" + "\x04\x00" + "\x04\x00" + "\x05" + "\x55\x53\x45\x52\x4e\x41\x4d\x45\x00\x00\x00\x00\x00\x00\x00\x00" + "\x06" + "\x50\x41\x53\x53\x57\x4f\x52\x44\x00\x00\x00\x00\x00\x00\x00\x00" + "\x00" + "\x41\x44\x4d\x49\x4e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + "\x00" + "\x49\x53\x41\x57\x45\x53\x4f\x4d\x45\x00\x00\x00\x00\x00\x00\x00" + "\x63\x61\x70\x74\x61\x69\x6e\x66\x61\x6c\x63\x6f\x6e\x00\x00\x00" + "\x66\x63\x30\x33\x33\x32\x39\x35\x30\x35\x34\x37\x35\x64\x64\x34\x62\x65\x35\x31\x36\x32\37\x63\x63\x37\x66\x30\x62\x31\x66\x31" + "\x01" + "\x01" + "\x63\x61\x70\x74\x61\x69\x6e\x66\x61\x6c\x63\x6f\x6e\x00\x00\x00" + "\x66\x63\x30\x33\x33\x32\x39\x35\x30\x35\x34\x37\x35\x64\x64\x34\x62\x65\x35\x31\x36\x32\37\x63\x63\x37\x66\x30\x62\x31\x66\x31" + "\x01" + "\x01" + "\x63\x61\x70\x74\x61\x69\x6e\x66\x61\x6c\x63\x6f\x6e\x00\x00\x00" + "\x66\x63\x30\x33\x33\x32\x39\x35\x30\x35\x34\x37\x35\x64\x64\x34\x62\x65\x35\x31\x36\x32\37\x63\x63\x37\x66\x30\x62\x31\x66\x31" + "\x01" + "\x01" + "\x63\x61\x70\x74\x61\x69\x6e\x66\x61\x6c\x63\x6f\x6e\x00\x00\x00" + "\x66\x63\x30\x33\x33\x32\x39\x35\x30\x35\x34\x37\x35\x64\x64\x34\x62\x65\x35\x31\x36\x32\37\x63\x63\x37\x66\x30\x62\x31\x66\x31" + "\x01" + "\x01"' > hex_file
```

Once we have the file, we could submit it like this:

```
$	python wololo_x.py 54.164.98.39 2510 hex_file
```

With that, the challenge would be solved. Again I would like to give credit to the writeup `http://tasteless.eu/post/2014/09/csaw-2014-quals-wololo-rev300/` which this is based off of.
