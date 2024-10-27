import os
import sys
import json
import socket
import Rsa
import hashlib
from datetime import datetime

class TransportAuthority:

    def __init__(self, id, ip, port, publickeys, authority_port, name):
        self.id = id
        self.ip = ip
        self.port = port
        self.rsa  = Rsa.Rsa()
        self.kPu, self.kPr = self.rsa.generate_rsa_keys()
        self.name = name
        self.authority_port = authority_port
        self.publickeys = publickeys

    def hash(self, cert):
        # Encode the text as bytes (UTF-8 encoding is commonly used)
        text_bytes = cert.encode('utf-8')
    
        # Compute the SHA-256 hash
        sha256_hash = hashlib.sha256(text_bytes).hexdigest()

        return sha256_hash

    def getpu(self, sa):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", self.authority_port))

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
        req = json.dumps({
            "reqtype": "getkey",
            "signingAuthority": sa,
            "timestamp": timestamp
        })

        print("Waiting for certificate...")
        s.send(req.encode())

        resp = json.loads(s.recv(1024).decode())["signed_cert"]
        print("Key Obtained: ", resp)
        return resp


    def verify(self, cert, sign, sa):
        """Verfication"""
        if sa not in self.publickeys:
            self.publickeys[sa] = self.getpu(sa)

        d, n = self.publickeys[sa]
        return True if self.hash(cert) == self.rsa.rsa_decrypt(sign, (d, n)) else False


    def Incomingreq(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", self.port))
        s.listen(5)

        print(f"Listening for connection on port [{self.port}]")
        while(True):
            c, addr = s.accept()
            print("Connection received from", addr)
            msg = json.loads(c.recv(1024).decode())
            print('Got message', msg)
            print("Message Sent at:", msg['timestamp'])
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')             

            if msg['reqtype'] == "verify":
                # Need to verify the certificate and respond
                res = self.verify(msg['cert'], msg['sign'], msg['signingAuthority'])
                resp = json.dumps({
                    "reply": ("Verfied" if res else "Not Verfied"),
                    "timestamp" : timestamp
                })
                print("Replying with ", resp)
                c.send(resp.encode())
            else:
                resp = json.dumps({
                    "signed_cert": self.publickeys[msg["signingAuthority"]],
                    "timestamp" : timestamp
                })
                print("Replying with:", resp)
                c.send(resp.encode())
        return

def main():
    if (len(sys.argv) != 5): 
        print("Invalid Arguments: python client.py [nodeid] [ipaddr] [port] [Name]")
        exit(0)
    id = int(sys.argv[1])
    ip = sys.argv[2]
    port = int(sys.argv[3])
    name = sys.argv[4]

    na = int(input("National TransportAuthority: "))
    publickeys = {}
    authority_port = None
    if(na == 1):
        num = int(input("Enter Number of RTOs: "))
        for rto in range(num):
            name = input("Name: ")
            kPu  = eval(input("Public Key: "))
            publickeys[name] = kPu
    else:
        authority_port = int(input("National RTO Port: "))

    ta = TransportAuthority(id, ip, port, publickeys, authority_port, name) 
    if(authority_port != None): 
        print(f"RTO establised with \npublickey {ta.kPu} and \nprivatekey {ta.kPr} on port {ta.port}")
    while(True):
        ta.Incomingreq()
    return


if __name__ == '__main__': main()
