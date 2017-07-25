#Designate the string which we need the output of the encryption to be
string = "FLAG23456912365453475897834567"

#Specify the output string
out = ""

#Run the loop which will reverse the encryption logic, and add each byte to the output string
for i in string:
	x = ord(i)
	x = ord(i)
	x = x - 9
	x = x ^ 0x10
	x = x - 20
	x = x ^ 0x50
	out += chr(x)

#Print the result
print out

