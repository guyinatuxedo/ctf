# dragon

This is just a basic reversing challenge. The flag is simply stored in the binary unaltered, so you can just view it using the strings command:

```
$	strings dragon | grep flag
flag{31b9307b77418383}
display_flag
```

Just like that, we captured the flag without even having to run it. But let's run it just for fun:

```
$	./dragon 
                                  /   \       
 _                        )      ((   ))     (
(@)                      /|\      ))_((     /|\
|-|                     / | \    (/\|/\)   / | \                      (@)
| | -------------------/--|-voV---\`|'/--Vov-|--\---------------------|-|
|-|                         '^`   (o o)  '^`                          | |
| |                               `\Y/'                               |-|
|-|                                                                   | |
| |                Welcome to Hungry Hungry Dragons!                  |-|
|-|                                                                   | |
| |                                                                   |-|
|_|___________________________________________________________________| |
(@)              l   /\ /         ( (       \ /\   l                `\|-|
                 l /   V           \ \       V   \ l                  (@)
                 l/                _) )_          \I
                                   `\ /'

```
