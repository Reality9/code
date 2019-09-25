
import sys, time
data = sys.argv[1]
key = sys.argv[2]
origkey = key
def xor_crypt_string(data, key=key, encode=False, decode=False):
    from itertools import izip, cycle
    import base64
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored

cipherdata = xor_crypt_string(data, encode=False)

hex = key.encode("hex")
number = int(hex, base=16)

c=0
for i in range(int(str(number)[:7])):
	c+=1;newkey = "";
	if c == (len(key)-1):
		c = 0
	try:
		newletter = chr(ord(key[c])-c)
	except:
		newletter = chr(ord(origkey[c])-c)
	i=1
	for i in range(len(key)):
		if i == c:
			newkey+=(str(newletter))
		else:
			newkey+=(str(key[i]))
	key = newkey
	cipherdata = xor_crypt_string(cipherdata, key=newkey, encode=False)
print(str(cipherdata))




