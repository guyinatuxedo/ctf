# This is based off of: https://github.com/perfectblue/ctf-writeups/tree/master/insomnihack-teaser-2019/junkyard

from Crypto.Cipher import AES

# Establish the IV, charSet, and CipherText
IV = "1234123412341234"
cipherText = "b0234db3e7823748303290fb70cd9eb220574e1e031f9741c332af2147396bc59e6a48b8dbce4606362102c977a185a69ebdf5f2bc967552f09f1ba49bb15753".decode('hex')
charSet = "ABCDEFGHIJKLMNOPQRS"

# This is a function which will generate the second and third portions from the first part
def numConvert(value):
    output = str(value)
    while value:
        output += charSet[value%10]
        value = value / 10
    output += "a"*(16 - len(output))
    return output

# Brute force the key, try values between 0 - 9999999999 for first part of the key 
for i in xrange(9999999999):
    # First part of the key is i
    key = numConvert(i)

    # Try to decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(cipherText)

    # Check if the text contains "INS" (which for this ctf the flag format is INS{flag_here})
    if "INS" in decrypted:
        print "decrypted: " + decrypted
        print "using key: " + key

