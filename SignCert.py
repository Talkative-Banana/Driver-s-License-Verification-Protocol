import hashlib
import sys
import Rsa


def hash(cert):
    # Encode the text as bytes (UTF-8 encoding is commonly used)
    text_bytes = cert.encode('utf-8')
    
    # Compute the SHA-256 hash
    sha256_hash = hashlib.sha256(text_bytes).hexdigest()

    return sha256_hash


def sign(cert, key):
    rsa = Rsa.Rsa()
    return rsa.rsa_encrypt(hash(cert), key)


def main():
    if (len(sys.argv) != 3):
        print("Invalid Arguments python SignCert.py [Cert] [privatekey]")

    cert = sys.argv[1]
    key  = eval(sys.argv[2])

    print("Certificate: ", cert)
    print("Signature:", sign(cert, key))
    return

if __name__ == '__main__': main()
