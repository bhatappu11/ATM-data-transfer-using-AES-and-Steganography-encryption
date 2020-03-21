# AES 256 encryption/decryption using pycrypto library
import base64
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Protocol.KDF import PBKDF2
from PIL import Image
import stepic


BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

password = input("Enter encryption password: ")
im = Image.open('ste.jpg')

def get_private_key(password):
    salt = b"this is a salt"
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

def encrypt(raw, password):
    private_key = get_private_key(password)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(bytes(raw,encoding="utf-8")))


def decrypt(enc, password):
    private_key = get_private_key(password)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


# First let us encrypt secret message
str=input("enter the account number")
encrypted = encrypt(str, password)

str1=input("enter the pin")
encrypted1 = encrypt(str1, password)
#print(encrypted1)

#print(encrypted)
im1 = stepic.encode(im, encrypted)
im1.save('ste.jpg', 'PNG')
im1 = Image.open('ste.jpg')
im1.show()


# Let us decrypt using our original password
      #Decode the image so as to extract the hidden data from the image
im2 = Image.open('ste.jpg')
stegoImage = stepic.decode(im2)
print(stegoImage)

decrypted = decrypt(stegoImage, password)

print(bytes.decode(decrypted))
decrypted1 = decrypt(encrypted1, password)
print(bytes.decode(decrypted1))
