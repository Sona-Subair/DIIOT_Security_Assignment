
import base64
from pickle import FALSE, TRUE
import urllib.request
import math
import numpy
import itertools
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def Hex_to_base64(data_str):
    
    data_bytes=bytes.fromhex(data_str)
    print(data_bytes)
    encoded_bytes= base64.b64encode(data_bytes,altchars=None)
    encoded_string=encoded_bytes.decode("utf-8")
    print(encoded_string)

def XOR_Combination(str1,str2):
    data_bytes1=int(str1,16)
    data_bytes2=int(str2,16)
    result=data_bytes1 ^ data_bytes2
    hex_result=format(result,'x') 
    print(hex_result)

def Single_byte_XOR_cipher_hex(str):
    hex_converted = bytes.fromhex(str)
    strings = (''.join(chr(h ^ key) for h in hex_converted) for key in range(256))
    result=max(strings, key=lambda s: s.count(' '))
    return(result)
   

def Single_byte_XOR_cipher(block):
    current_key=''
    highest_count=0
    frequent_key = 'ETAOIN SHRDLU'
    #hex_converted = bytes(str,encoding='utf8')
    for key in range(256):
        count=0
        xor_value = [(key ^ h) for h in block]
        xor_value=bytes(xor_value)
        string=str(xor_value)
        for k in string.upper():
            if k in frequent_key:
                count=count+1
        if count>highest_count:
            highest_count=count
            current_key=chr(key).upper()            
    return(current_key)

def find_encrypted_string():
    target_url="https://cryptopals.com/static/challenge-data/4.txt"
    f=urllib.request.urlopen(target_url)
    for line in f:
        str=line.decode("utf-8")
        cipher_result=Single_byte_XOR_cipher_hex(str)
        if all(chr.isalpha() or chr.isspace() for chr in cipher_result):
            print(cipher_result)  
        line = f.readline()  

def repeated_key_encrypt(string,key):
    key_str=key
    num=math.ceil(len(string)/len(key))
    for i in range (0,num-1):
        key_str=key_str+key
    key_str=key_str[:len(string)]  
    #data_bytes_str=bytes(string, 'utf-8')
    data_bytes_key=bytes(key_str, 'utf-8')
    result=int.from_bytes(string, byteorder="big") ^ int.from_bytes(data_bytes_key, byteorder="big")
    hex_result=format(result,'x') 

def hamming_distance(str1:bytes,str2:bytes):
    hamming_dist=0
    byte1=int.from_bytes(str1, byteorder="big") 
    byte2=int.from_bytes(str2, byteorder="big")
    hamming_dist+=bin(byte1^byte2).count('1')
    return(hamming_dist)

def break_repeating_key_XOR():
    target_url="https://cryptopals.com/static/challenge-data/6.txt"
    f=urllib.request.urlopen(target_url)
    text=f.read()
    k_size_norm=[]
    key=''
    decoded_bytes= base64.urlsafe_b64decode(text)
    for k in range (2,40):
        byte1=decoded_bytes[:k]
        byte2=decoded_bytes[k:(2*k)]
        h_dist=hamming_distance(byte1,byte2)
        k_size_norm.append(math.ceil(h_dist/k))  
    k_size=math.ceil(sum(sorted(k_size_norm)[:4])/4)
    print(k_size)
    chunks = dict.fromkeys(range(k_size))
    i = 0
    for octet in decoded_bytes:
        if (i == k_size): i = 0
        if (chunks[i] == None): chunks[i] = []
        chunks[i].append(octet)
        i += 1
    for j in range (0,k_size):
        current_key=Single_byte_XOR_cipher(chunks[i])
        key+=current_key
    print(key)    
    repeated_key_encrypt(decoded_bytes,key)    

def AES_Decrypt(txt,key):
    txt_bytes=base64.b64decode(txt)
    key=bytes(key,encoding='ascii')
    cipher = Cipher(algorithms.AES(key),modes.ECB())
    decryptor = cipher.decryptor()
    val=decryptor.update(txt_bytes) + decryptor.finalize()
    return (str(val,encoding='ascii'))


    
data_str="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
str1="1c0111001f010100061a024b53535009181c"
str2="686974207468652062756c6c277320657965"
str3="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
XOR_Combination(str1,str2)
cipher_result=Single_byte_XOR_cipher_hex(str3)
print(cipher_result)
find_encrypted_string()
break_repeating_key_XOR()
Aes_key="YELLOW SUBMARINE"
target_url="https://cryptopals.com/static/challenge-data/7.txt"
f=urllib.request.urlopen(target_url)
text=f.read()
decrypted_data=AES_Decrypt(text,Aes_key)
print(decrypted_data)
target_url="https://cryptopals.com/static/challenge-data/8.txt"
f=urllib.request.urlopen(target_url)
hex_text=f.read()
key="abcdefghijklmnop"
#Detect_Aes_string(cipher_text,key)