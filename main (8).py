from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

FLAG = b'AKASEC{test_flag}'

class RSA:
    def __init__(self, msg):
        self.msg = bytes_to_long(msg)

    def getPubKey(self):
        p = getPrime(128)
        q = getPrime(128)
        n = p * q
        return p, q, n, 0x10001

    def get_hints(self, p):
        ns = [getPrime(64) for i in range(3)]
        bs = [p % ns[i] for i in range(3)]
        N1 = ns[1]*ns[2]
        N2 = ns[0]*ns[2]
        return N1, N2, ns[1], bs


    def encrypt(self):
        p, q, n, e = self.getPubKey()
        ct = pow(self.msg, e, n)
        return p, q, e, n, ct

rsa = RSA(FLAG)
p, q, e, n, ct = rsa.encrypt()
N1, N2, n2, bs = rsa.get_hints(p)
    
print(f'e = {e}')
print(f'n = {n}')
print(f'ciphertext = {ct}')
print(f'N1 = {N1}')
print(f'N2 = {N2}')
print(f'n2 = {n2}')
print(f'bi = {bs}')
