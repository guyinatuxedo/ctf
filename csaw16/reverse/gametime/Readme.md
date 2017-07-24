So we are just given an exectuable and no server to connect to, so we just have to worry about the executable. When we run the game, we see that it prompts us to press certain keys when it displays certain letters (like press `m` when it displays `m`). Now it is actually possible to play the game and get the flag without hacking it, however we won't do that. First let's see what type of file it is:

```
$	file gametime.exe 
gametime.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So we can see that is a 32 bit Windows Executable. When we look at in IDA we see two strings that can be of interest to us:

```
.rdata:00417A80 0000002B C \rUDDER FAILURE! http://imgur.com/4Ajx21P \n
.rdata:00417AD0 0000002A C UDDER FAILURE! http://imgur.com/4Ajx21P \n
```

It is evident that this is a failer message, displayed when you loos the game.When we Xreference either strubg to see where it is called, we see that it is called after a test instruction like this:
```
loc_4014CA:
mov     edx, 186A0h
mov     ecx, esi
call    sub_401260
pop     edi
pop     esi
pop     ebx
test    al, al
jnz     short loc_401503
```

We see in both instances that if the output of the `test` instruction is not 0, we can continue playing the game. So we should be able to edit the assembly code to change the `jnz` to `jz`, that way if we don't do anything, the output of the `test` instruction should be 0 and we should be able to continue playing the game. We can see that the two functions which these two strings are called are `sub_401435` and `sub_401507` (at the very beginning of the viewing the assembly code in proximity view we can see the function it is a part of). We can edit it using Binary Ninja. 

To edit it in Binary Ninja, just open the exectuable in it, go to each of the two functions (`sub_401507` and `sub_401435`), right click on the line we want to edit, go to Patch->Edit Current Line and then just change `jne` to `je`. Lastly just save it. After that you should just be able to run the exe in windows, not give it any input, and evantually it will print the flag (which isn't in the standard format):

```
key is <no5c30416d6cf52638460377995c6a8cf5>
```

Just like that, we get the flag which is `no5c30416d6cf52638460377995c6a8cf5`.