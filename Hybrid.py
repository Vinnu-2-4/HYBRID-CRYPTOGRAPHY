import secrets
import random
import sys
import time
from Crypto.Cipher import AES


def gcd(a, b):
    #Euclid's algorithm
    while b != 0:
        temp = a % b
        a = b
        b = temp
    return a


def multiplicativeinverse(a, b):
    #Euclid's extended algorithm
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a
    ob = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob
    if ly < 0:
        ly += oa
    return lx


def generateprime(keysize):
    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** (keysize))
        if isprime(num):
            return num


def isprime(num):
    if (num < 2):
        return False  # 0, 1, and negative numbers are not prime
    lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
                 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
                 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
                 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
                 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
                 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653,
                 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
                 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowprimes:
        return True

    for prime in lowprimes:
        if (num % prime == 0):
            return False

    return millerrabin(num)


def millerrabin(n, k=7):
    if n < 6:
        return [False, False, True, True, False, True][n]
    elif n & 1 == 0:
        return False
    else:
        s, d = 0, n - 1
        while d & 1 == 0:
            s, d = s + 1, d >> 1
        for a in random.sample(range(2, min(n - 2, sys.maxsize)), min(n - 4, k)):
            x = pow(a, d, n)
            if x != 1 and x + 1 != n:
                for r in range(1, s):
                    x = pow(x, 2, n)
                    if x == 1:
                        return False
                    elif x == n - 1:
                        a = 0
                        break
                if a:
                    return False
        return True


def KeyGeneration(size=8):
    # 1)Generate 2 large random primes p,q (same size)
    p = generateprime(size)
    q = generateprime(size)
    if not (isprime(p) and isprime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # 2)compute n=pq and phi=(p-1)(q-1)
    n = p * q
    phi = (p - 1) * (q - 1)

    # 3) select random integer "e" (1<e<phi) such that gcd(e,phi)=1
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # 4)Use Extended Euclid's Algorithm to compute another unique integer "d" (1<d<phi) such that e.d≡1(mod phi)
    d = multiplicativeinverse(e, phi)

    # 5)Return public and private keys
    # Public key is (e, n) and private key is (d, n)
    return ((n, e), (d, n))


def encrypt(pk, plaintext):
    # 1) obtain (n,e)
    n, e = pk
    # 2)message space [0,n-1]
    # 3)compute c=m^e(mod n)
    c = [(ord(char) ** e) % n for char in plaintext]
    # 4) send "C" to the other party
    return c


def decrypt(pk, ciphertext):
    d, n = pk
    # 5)m=c^d (mod n)
    m = [chr((char ** d) % n) for char in ciphertext]
    return m


def encryptAES(cipherAESe, plainText):
    return cipherAESe.encrypt(plainText.encode("utf-8"))


def decryptAES(cipherAESd, cipherText):
    dec = cipherAESd.decrypt(cipherText).decode('utf-8')
    return dec

def user():
    plaintext = input("Enter the message:")
    print("Given user message:",plaintext)
    return plaintext


def fromfile():
    text = open("Give the file path from your local disk", "r")
    print("")
    string=text.read()
    print("Original message in the File:\n",string)
    text.close()
    return string
def exit1():
    exit()


def main():
    # To encrypt a message addressed to Alice in a hybrid crypto-system, Bob does the following:
    print("******************************************************************")
    print("Welcome to the hybrid cryptographic scheme demostration...")
    print("******************************************************************")
    print("We're going to encrypt and decrypt a message using AES and RSA")
    print("******************************************************************")


    print("")
    print("Generating RSA public and Privite keys......")
    pub, pri = KeyGeneration()
    print("Public:",pub)
    print("Private Keys:",pri)
    time.sleep(2)

    # 2.	Generates a fresh symmetric key for the data encapsulation scheme.
    print("")
    print("Generating AES symmetric key......")
    key = secrets.token_hex(16)
    print("")
    print("AES Symmetric Key:",key)
    KeyAES = key.encode('utf-8')

    # 3.	Encrypts the message under the data encapsulation scheme, using the symmetric key just generated.

    while True:
        print("Menu:\n 1.Give user input.\n 2.Import  Text from a File in your Local Disk.\n 3.Exit ")
        choice = int(input("Enter Your Choice:"))
        if choice<1 or choice>3:
            print("Invalid Option choose Other Option")
            continue
        switcher = {
            1: user,
            2: fromfile,
            3: exit1
        }
        func = switcher.get(choice, lambda: 'invalidoption')
        text = func()
        if text==exit1:
            break
        cipherAESe = AES.new(KeyAES, AES.MODE_GCM)
        nonce = cipherAESe.nonce
        print("Encrypting the message with AES Symmetric Key......")
        cipherText = encryptAES(cipherAESe, text)
        time.sleep(2)
        print("")
        print("AES cypher text:",cipherText)
        time.sleep(2)
        print("")

        # 4.	Encrypt the symmetric key under the key encapsulation scheme, using public key.
        cipherKey = encrypt(pub, key)
        print("Encrypting the AES symmetric key with RSA......")
        time.sleep(2)
        print("")
        print("Encryted AES symmetric key:",cipherKey)
        time.sleep(2)
        # 5.	Send both of these encryptions.
        # Sending.........

        # To decrypt this hybrid cipher-text

        # 1.	Useing  private key to decrypt the symmetric key contained in the key encapsulation segment.
        decriptedKey = ''.join(decrypt(pri, cipherKey))
        print("")
        print("Decrypting the AES Symmetric Key...")
        time.sleep(2)
        print("")
        print("AES Symmetric Key:",decriptedKey)
        time.sleep(2)
        print("")


        # 2.	Uses this symmetric key to decrypt the message contained in the data encapsulation segment.
        decriptedKey = decriptedKey.encode('utf-8')
        cipherAESd = AES.new(decriptedKey, AES.MODE_GCM, nonce=nonce)
        decrypted = decryptAES(cipherAESd, cipherText)
        print("Decrypting the message using the AES symmetric key.....")
        print("")
        time.sleep(2)
        print("decrypted message:\n",decrypted)


if __name__ == "__main__":
    main()
