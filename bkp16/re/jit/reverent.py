enc_flag = "FMTEPB}U3`_YEl0jj_hYcpp0emuYcv_Yu4Y355<w"
flag = ""

for i in enc_flag:
    x = ((ord(i) + 1) ^ 0x5)
    flag += chr(x)

print "[+] The flag is: " + flag
