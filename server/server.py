#!/usr/bin/env python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
import os
import select
import socket
import sys
import time
import uuid

def available(conn):
	try:
		readable,writeable,errored=select.select([conn],[],[],0)
		if conn in readable:
			return True
	except KeyboardInterrupt:
		exit(1)
	except:
		pass
	return False

class client_t:
	def __init__(self,uid,sock):
		self.uid=uid
		self.sock=sock
		self.secret=''
		print(self.uid+': New client.')
		self.sock.settimeout(5)

	def update(self):
		if not self.sock:
			return True
		try:
			pubkey=self.sock.recv(1096)
			if len(pubkey)!=1096:
				print(self.uid+': Invalid public key size.')
				self.sock.close()
				return False
			print(self.uid+': Received public key.')
			pubkey=pubkey.decode('hex')
			pubkey=RSA.importKey(pubkey)
			cipher=PKCS1_OAEP.new(pubkey)
			print(uid+': Public key loaded.')
			self.key=os.urandom(32)
			self.iv=os.urandom(16)
			cipher=cipher.encrypt(self.uid+self.key+self.iv)
			print(self.uid+': Encrypted uid and secret.')
			self.sock.send(cipher)
			print(self.uid+': Sent encrypted info.')
			self.sock.close()
			self.sock=None
			return True
		except:
			self.sock.close()
			return False

if __name__=='__main__':
	addr="127.0.0.1"
	port=4444
	sock=socket.socket()
	sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
	sock.bind((addr,port))
	sock.listen(1)
	print('Listening on '+addr+':'+str(port)+'.')
	clients={}
	while True:
		if available(sock):
			client,addr=sock.accept()
			uid=str(SHA.new(str(uuid.uuid1())).hexdigest())
			clients[uid]=client_t(uid,client)
		keep_clients={}
		for key in clients:
			if clients[key].update():
				keep_clients[key]=clients[key]
			else:
				print(key+': Removed.')
		clients=keep_clients
		time.sleep(0.1)