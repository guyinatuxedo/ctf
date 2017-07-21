x0 = "themidathemidathem"
x1 = ">----++++....<<<<."

a = [0]*18

i = 0
for i in xrange(18):
    x = ord(x0[i])
    y = ord(x1[i])
    z = x ^ y
    a[i] = z + 22
#print a

b ="" 

for i in xrange(18):
    b += chr(a[i] + 9)
#    print chr(b[i])
print b
