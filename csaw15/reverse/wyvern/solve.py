#Establish the values we got from Hero
diff = [ 0x0, 0x64, 0xD6, 0x10A, 0x171, 0x1A1, 0x20F, 0x26E, 0x2DD, 0x34F, 0x3AE, 0x41E, 0x452, 0x4C6, 0x538, 0x5A1, 0x604, 0x635, 0x696, 0x704, 0x763, 0x7CC, 0x840, 0x875, 0x8D4, 0x920, 0x96C, 0x9C2, 0x0A0F]

#Establish the list, and the string which will hold the secret
secret_list = [-1]*29 
secret = ""

#For loop to calculate the differences, convert them to ASCII, and store them in the list
for i in xrange(1, 29):
    secret_list[i] = chr(diff[i] - diff[i - 1])

#Consolidate the list into the string, and print it
secret = secret.join(secret_list[1:])
print secret

