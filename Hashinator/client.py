#!/usr/bin/python

from pwn import *
import re

def process_data(data):

	pw_template = re.compile(r'Challenge password hash: b\'(.*)\'')
	passwordhash = pw_template.search(data[0]).group(1)


	hash_rounds = [s[2:] for s in data[3:34]]

	log.info("password hash %s" % passwordhash)
	log.info("hash rounds %s" % ','.join(hash_rounds))
	return passwordhash, hash_rounds

def main():
	p = remote("47.88.216.38", 20013)

	data = p.recvrepeat(0.2)
	log.info(data)

	data = p.recvlines(35)
	log.info('\n'.join(data))

	pwhash, hash_rounds = process_data(data)