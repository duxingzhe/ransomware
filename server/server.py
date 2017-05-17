#!/usr/bin/env python2
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
import json
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

    def __init__(self,uid,sock,key='',iv=''):
        self.uid=uid
        self.sock=sock
        self.key=key
        self.iv=iv
        print(self.uid+': New client.')
        if self.key:
            print(self.uid+': key is '+self.key.encode('hex'))
        if self.iv:
            print(self.uid+': iv  is '+self.iv.encode('hex'))
        if sock:
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
            print(self.uid+': key is '+self.key.encode('hex'))
            print(self.uid+': iv  is '+self.iv.encode('hex'))
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

    def to_dict(self):
        if len(self.uid)>0 and len(self.key)>0 and len(self.iv)>0:
            obj={}
            obj['uid']=self.uid
            obj['key']=self.key.encode('hex')
            obj['iv']=self.iv.encode('hex')
            return obj
        return None

def clients_to_dict(clients):

    clients_dict={}
    for key in clients:
        client_dict=clients[key].to_dict()
        if client_dict:
            clients_dict[key]=clients[key].to_dict()
    return clients_dict

def load_json():

    try:
        return_clients={}
        with open('clients.json','r') as f:
            clients=f.read()
            f.close()
            clients=json.loads(clients)
            for key in clients:
                client=clients[key]
                return_clients[client['uid']]=client_t(client['uid'],None,
                    client['key'].decode('hex'),client['iv'].decode('hex'))
        return return_clients
    except Exception as error:
        print('Error reading load file - '+str(error))
        return {}

def save_json(clients):
    
    try:
        with open('clients.json','w') as f:
            f.write(json.dumps(clients_to_dict(clients)))
            f.close()
    except Exception as error:
        print('Error writing save file - '+str(error))

if __name__=='__main__':
    try:
        addr='127.0.0.1'
        port=4444
        sock=socket.socket()
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        sock.bind((addr,port))
        sock.listen(1)
        print('Listening on '+addr+':'+str(port)+'.')
        clients=load_json()
        while True:
            if available(sock):
                client,addr=sock.accept()
                uid=str(SHA.new(str(uuid.uuid1())).hexdigest())
                clients[uid]=client_t(uid,client)
            keep_clients={}
            for key in clients:
                if clients[key].update():
                    keep_clients[key]=clients[key]
                    save_json(keep_clients)
                else:
                    print(key+': Removed.')
            clients=keep_clients
            time.sleep(0.1)
    except KeyboardInterrupt:
        exit(1)
    except Exception as error:
        print('Error - '+str(error))
        exit(1)
