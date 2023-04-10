import base64
from Crypto.Cipher import DES
from Crypto.Hash import MD5

def decrypt(encrypted_string, key):
    des = DES.new(MD5.new(key).digest()[:8], DES.MODE_ECB)
    decrypted_string = des.decrypt(base64.b64decode(encrypted_string))

    return decrypted_string
arr = ["mB5p/eSomXuy99pokz9GEw==","H3lwRG3O4rSY/DRpRTJANJreRWQHCGDcAqbU3gZVRRvyfM00Z0dIigKXPAaZce3C"]
for el in arr:
	print(decrypt(el,
		b"BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfkLkJrkDExMvkEUCxUkUGr"))

