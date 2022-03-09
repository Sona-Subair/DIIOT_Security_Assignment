
import base64
from pickle import FALSE, TRUE
import urllib.request
import math
import numpy
import itertools

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

def Single_byte_XOR_cipher(str):
    hex_converted = bytes.fromhex(str)
    strings = (''.join(chr(h ^ key) for h in hex_converted) for key in range(256))
    result=max(strings, key=lambda s: s.count(' '))
    return(result)

def find_encrypted_string():
    target_url="https://cryptopals.com/static/challenge-data/4.txt"
    f=urllib.request.urlopen(target_url)
    for line in f:
        str=line.decode("utf-8")
        cipher_result=Single_byte_XOR_cipher(str)
        if all(chr.isalpha() or chr.isspace() for chr in cipher_result):
            print(cipher_result)  
        line = f.readline()  

def  repeated_key_encrypt(string,key):
    key_str=key
    num=math.ceil(len(string)/len(key))
    for i in range (0,num-1):
        key_str=key_str+key
    key_str=key_str[:len(string)]  
    data_bytes_str=bytes(string, 'utf-8')
    data_bytes_key=bytes(key_str, 'utf-8')
    result=int.from_bytes(data_bytes_str, byteorder="big") ^ int.from_bytes(data_bytes_key, byteorder="big")
    hex_result=format(result,'x') 
    print(hex_result)

def hamming_distance(str1:bytes,str2:bytes):
    hamming_dist=0
    byte1=int.from_bytes(str1, byteorder="big") 
    byte2=int.from_bytes(str2, byteorder="big")
    hamming_dist+=bin(byte1^byte2).count('1')
    print(hamming_dist)
    return(hamming_dist)

def break_repeating_key_XOR():
    target_url="https://cryptopals.com/static/challenge-data/6.txt"
    f=urllib.request.urlopen(target_url)
    text=f.read()
    k_size_norm=[]
    decoded_bytes= base64.urlsafe_b64decode(text)
    for k in range (2,40):
        byte1=decoded_bytes[:k]
        byte2=decoded_bytes[k:(2*k)]
        h_dist=hamming_distance(byte1,byte2)
        k_size_norm.append(math.ceil(h_dist/k))  
    k_size=math.ceil(sum(sorted(k_size_norm)[:4])/4)
    print(k_size)
    matrix=[decoded_bytes[i:i+k_size] for i in range(0, len(decoded_bytes), k_size)]
    matrix= itertools.zip_longest(*matrix, fillvalue='0')
    numpy.transpose(matrix)
    #char_freqs = [Single_byte_XOR_cipher(''.join(matrix))][2]
    #print(char_freqs)
    char_freqs = Single_byte_XOR_cipher(''.join(matrix))
    print(char_freqs)
    
data_str="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
str1="1c0111001f010100061a024b53535009181c"
str2="686974207468652062756c6c277320657965"
str3="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
XOR_Combination(str1,str2)
cipher_result=Single_byte_XOR_cipher(str3)
print(cipher_result)
find_encrypted_string()
repeated_key_encrypt("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal","ICE")
#hamming_distance("this is a test","wokka wokka!!!")
break_repeating_key_XOR()