#!/usr/bin/python

from pwn import *
import os
import hashlib
import socket
import threading
import socketserver
import struct
import time
import pyscrypt
from base64 import b64decode

def md5(bytestring):
    return hashlib.md5(bytestring).digest()

def sha(bytestring):
    return hashlib.sha1(bytestring).digest()

def blake(bytestring):
    return hashlib.blake2b(bytestring).digest()

def scrypt(bytestring):
    l = int(len(bytestring) / 2)
    salt = bytestring[:l]
    p = bytestring[l:]
    # return hashlib.scrypt(p, salt=salt, n=2**16, r=8, p=1, maxmem=67111936)
    return pyscrypt.hash(p, salt = salt, N = 2**16, r = 8, p = 1, dkLen = 64)

def xor(s1, s2):
    return b''.join([bytes([s1[i] ^ s2[i % len(s2)]]) for i in range(len(s1))])


def decode(payload):
    dec = b64decode(payload)
    print(type(dec), dec)
    return dec


def reverse_hash(payload, hash_rounds):
    interim_salt = payload[:64]
    interim_hash = payload[64:]
    for i in range(len(hash_rounds)):
        hashed_salt = bytearray()
        hashed_salt.extend(hash_rounds[-1-i](interim_salt))
        interim_hash = xor(interim_hash, hashed_salt)

        hashed_hash = bytearray()
        hashed_hash.extend(hash_rounds[i](interim_salt))
        interim_salt = xor(interim_salt, hashed_hash)
        
    original_hash = interim_salt + interim_hash
    return original_hash

hashes = [md5, sha, blake, scrypt]
name_map = {"md5": md5, "sha": sha, "blake": blake, "scrypt": scrypt}

#!/usr/bin/python

from pwn import *
import re

def process_data(data):

	pw_template = re.compile(r'Challenge password hash: b\'(.*)\'')
	passwordhash = pw_template.search(data[0]).group(1)


	hash_rounds = [s[2:] for s in data[3:34]]

	log.info("password hash %s" % passwordhash)
	log.info("hash rounds %s" % ','.join(hash_rounds))
	return passwordhash, [name_map[s] for s in hash_rounds]

def main():
	p = remote("47.88.216.38", 20013)

	data = p.recvrepeat(0.2)
	log.info(data)

	data = p.recvlines(35)
	log.info('\n'.join(data))

	pwhash, hash_rounds = process_data(data)
	
	pwhash = decode(pwhash)
	print(reverse_hash(pwhash, hash_rounds))
# payload = bytearray()
# payload.extend(b64decode(password_hash))
# print(type(payload), payload)
# password = reverse_hash(payload, hash_rounds)
# def calculate_hash(self, payload, hash_rounds):
#     interim_salt = payload[:64]
#     interim_hash = payload[64:]
#     for i in range(len(hash_rounds)):
#         interim_salt = xor(interim_salt, hash_rounds[-1-i](interim_hash))
#         interim_hash = xor(interim_hash, hash_rounds[i](interim_salt))
#     final_hash = interim_salt + interim_hash
#     return final_hash

# def main():

#     p = remote("47.88.216.38", 20013)

#     data = p.recvrepeat(0.2)

#     log.info(data)

if __name__ == '__main__':
	main()