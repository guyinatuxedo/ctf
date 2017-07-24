import itertools

thash = "0xd386d209"

characters = list("qwertyuioplkjhgfdsazxcvbnm")

def hash(string):
    beg_x = 0x1505
    x = beg_x << 5
    x = x + beg_x
    for i in string:
            x = x + ord(i)
            beg_x = x
            x = x << 5
            x = x + beg_x
    x = x + 10
    x = "0x" + hex(x)[-8:]
    return x

for c in range(1, 10):
    print "Cracking hash with length: " + str(c)
    for i in itertools.product(characters, repeat = c):
        ghash = hash(i)    
        if (ghash == thash):
            print "hash cracked: " + "".join(i)
            break





