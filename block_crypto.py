import urllib.request
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from random import Random
BLOCK_SIZE=16


def PKCS_Padding(text,size):
    length=len(text)
    if((length%size)==0):
        return text
    padding_size=size-(length%size)
    padding_value=hex(padding_size).lstrip("0x")
    if len(padding_value) == 1:
        padding_value = '0' + padding_value 
    padding_value = bytes.fromhex(padding_value)
    padded_string = (padding_value * padding_size)
    print(padded_string)
    return(padded_string)

def CBC_mode(lines):
    iv= "\x00" * 16
    iv=bytes(iv.lstrip('0x'),encoding='ascii')
    ciphertext = base64.b64decode(line)
    key = 'YELLOW SUBMARINE'
    key=bytes(key,encoding='ascii')
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext=decryptor.update(ciphertext) + decryptor.finalize()
    return(plaintext.decode('ascii'))

def encryption_oracle_CBC_ECB(message,key):
    mode = Random().randint(0, 1)
    iv=os.urandom(16)
    left_padding_cnt=Random().randint(5, 10)
    right_padding_cnt=Random().randint(5, 10)
    left_padding=os.urandom(left_padding_cnt)
    right_padding=os.urandom(right_padding_cnt)
    message=left_padding+message+right_padding
    size = 16
    length = len(message)
    if length % size != 0:
    # PKCS#7 padding if the plain-text after padding isn't a multiple of AES.BLOCK_SIZE
        padding = size - (length % size)
        padValue = hex(padding).lstrip('0x')
        if len(padValue) == 1:
            padValue = '0' + padValue 
        padValue = bytes.fromhex(padValue)
        message += padValue * padding
        print(len(message))
    if mode==1:
        cipher = Cipher(algorithms.AES(key),modes.ECB())
        encryptor = cipher.encryptor()
        val=encryptor.update(message) + encryptor.finalize()
    else:
        cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
        encryptor = cipher.encryptor()
        val=encryptor.update(message) + encryptor.finalize()
    print(len(val))    
    return(val)

def detect_encryption(ciphertext):
    print(ciphertext)
    chunkSize = 16
    chunks = []
    print(chunks)
    print(len)
    for i in range(0, len(ciphertext), chunkSize):
         chunks.append(ciphertext[i:i+chunkSize])
    print(chunks)
    print(len(chunks))
    uniquechunks= set(chunks)
    print(uniquechunks)
    print(len(uniquechunks))
    if len(chunks) > len(uniquechunks):
        return "ECB"
    return "CBC"

padded_key=PKCS_Padding("YELLOW SUBMARINE",20)
print(padded_key)
target_url="https://cryptopals.com/static/challenge-data/10.txt"
f=urllib.request.urlopen(target_url)
line = f.read()
CBC_decrypted=CBC_mode(line)
print(CBC_decrypted)
message = b"Crypto is fun but takes time"*3
key=os.urandom(16)
ciphertext = encryption_oracle_CBC_ECB(message,key) 
encryption_mode=detect_encryption(ciphertext)
print(encryption_mode)