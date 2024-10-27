import os
import sys
import json
import socket

from datetime import datetime

class Client:
    def __init__(self, id, ipaddr, port):
        self. id    = id
        self.ipaddr = ipaddr
        self.port   = port
    
    def sendl(self, ip, port, cert, sign, signingAuthority):
        # Send self.cert for verification
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))


        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        req = json.dumps({
            "reqtype" : "verify",
            "signingAuthority" : signingAuthority,
            "cert" : cert,
            "sign" : sign,
            "timestamp" : timestamp
        })

        print("Waiting for Verification")
        s.send(req.encode())

        resp = s.recv(1024).decode()
        print(resp)
        return resp


def main():
    if len(sys.argv) != 4:
        print("Invalid Arguments: python client.py [nodeid] [ipaddr] [port]")
        exit(0)

    id     = int(sys.argv[1])
    ipaddr = sys.argv[2]
    port   = int(sys.argv[3])
    client = Client(id, ipaddr, port)


    while(True):
        print("1) Send License for verification")
        print("2) Ext")
        inp = int(input())
        if inp == 1:
            ip   = input("Ip address: ")
            port = int(input("Port: "))
            sa   = input("signingAuthority: ")
            cert = input("Cert: " )
            sign = input("Sign: ")
            client.sendl(ip, port, cert, sign, sa)
        elif inp == 2:
            break
        else:
            print("Invalid Input")

    return

if __name__ == '__main__': main()
