
#Use: This process is only to be used to encrypt a data element in a deterministic way. Process was intented for data conversion, not streaming data across TCP/IP sessions.

import sys, time, hashlib, json, base64
data = sys.argv[1]
key = sys.argv[2]
def xor_crypt_string(data, key=key, encode=False, decode=False):
    from itertools import izip, cycle
    import base64
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored

def main(data,key):
	
	keyhash = hashlib.sha512(key)
	origkey = key
	cipherdata = xor_crypt_string(data, encode=True)
	hex = key.encode("hex")
	number = int(hex, base=16)
	c=0
	for i in range(int(str(number)[:7])):
		#key = re.sub(r'\W+', '', key)
		newkey = "";
		if c == (len(key)):
			c = 0
		try:
			newletter = chr(ord(key[c])-c)
		except:
			newletter = chr(ord(origkey[c])-c)
		i=0
		for i in range(len(key)):
			if i == c:
				newkey+=(str(newletter))
			else:
				newkey+=(str(key[i]))
		key = newkey

		cipherdata = xor_crypt_string(cipherdata, key=newkey, encode=False)
		#print(cipherdata.encode("hex"))
		c+=1;
	result = {}
	result['Ciphertext'] = str(cipherdata).encode("hex")
	result['Base64Ciphertex'] = str(base64.encodestring(cipherdata).strip())
	result['SHA512Ciphertext'] = str(hashlib.sha512(base64.encodestring(cipherdata).strip()).hexdigest())
	return(result)
print(main(data,key))






