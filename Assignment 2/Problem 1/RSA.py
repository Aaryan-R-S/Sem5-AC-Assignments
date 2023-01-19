from Crypto.Util import number
import gmpy2
import random

class RSA:
    def __init__(self, security_parameter):
        self.security_parameter = security_parameter
        ((n,e),(p,q,d)) = self.Keys() 

        self.pubKey = {"n": n, "e": e}
        self.privKey = {"p": p, "q": q, "d": d}

        self.blockSize = 32

    def gcd(a, b):
        while b != 0:
            (a, b) = (b, a%b)
        return a

    def Keys(self):
        p = number.getPrime(self.security_parameter)
        q = number.getPrime(self.security_parameter)

        while p == q:
            q = number.getPrime(self.security_parameter)
        
        n = p * q
        
        phi_n = (p-1) * (q-1)
        
        e = random.randint(2, phi_n-1)

        while RSA.gcd(e, phi_n) != 1:
            e = random.randint(2, phi_n-1)
    
        d = gmpy2.invert(e, phi_n)

        return ((n,e),(p,q,d))
    
    def Enc(self, m):
        if len(m) != self.blockSize:
            raise ValueError("[ERROR] Message to be encrypted must be a binary string of size 32 bits!")
            
        try:
            plain_num = int(m, 2)
            cipher_num = pow(plain_num, self.pubKey["e"], self.pubKey["n"])
            cipher_text = bin(cipher_num)[2:]
            return cipher_text

        except Exception as e:
            raise ValueError("[ERROR] Message to be encrypted must be a binary string of size 32 bits!")
    
    def Dec(self, c):
        try:
            cipher_num = int(c, 2)
            plain_num = pow(cipher_num, self.privKey["d"], self.privKey["p"] * self.privKey["q"])
            plain_text = bin(plain_num)[2:]
            return plain_text

        except Exception as e:
            raise ValueError("[ERROR] Ciphertext to be decrypted must be a binary string!")
    
if __name__ == "__main__":

    l = int(input("\nEnter security parameter in bits (e.g. 1024): "))
    myRSA = RSA(l)

    plain_text = input("\nEnter binary string of size 32 bits to be encrypted: ")
    cipher_text = myRSA.Enc(plain_text)
    print(f"\nEncrypted ciphertext: {cipher_text}")

    cipher_text = input("\nEnter binary string to be decrypted: ")
    plain_text = myRSA.Dec(cipher_text)
    print(f"\nDecrypted plaintext: {plain_text}\n")

