import random
from sympy import isprime, mod_inverse

class Rsa:
    def generate_prime(self, n_bits=1024):
        while True:
            prime_candidate = random.getrandbits(n_bits)
            if isprime(prime_candidate): return prime_candidate

    def generate_rsa_keys(self, n_bits=1024):
        p = self.generate_prime(n_bits)
        q = self.generate_prime(n_bits)
        n = p * q
        phi = (p-1) * (q-1)
        e = 65537
        d = mod_inverse(e, phi)
        return ((e, n), (d, n))
    
    def rsa_encrypt(self, message, public_key):
        e, n = public_key
        encrypted_blocks = []
        block_size = 245  # Adjust block size based on padding scheme
        for i in range(0, len(message), block_size):
            block = message[i:i+block_size]
            block_int = int.from_bytes(block.encode(), 'big')
            encrypted_int = pow(block_int, e, n)
            encrypted_blocks.append(encrypted_int)
        return encrypted_blocks

    def rsa_decrypt(self, encrypted_blocks, private_key):
        d, n = private_key
        decrypted_blocks = []
        for encrypted_int in eval(encrypted_blocks):
            decrypted_int = pow(int(encrypted_int), d, n)
            decrypted_block = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
            decrypted_blocks.append(decrypted_block)
        return ''.join(decrypted_blocks)
    
    def __init__(self):
        pass
