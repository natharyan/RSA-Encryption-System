import random
import hashlib

# Miller-Rabin Primality Test
def MillerRabin(n, p):
    a = random.randint(2, (n - 2) - 2)
    x = pow(a, int(p), n) 

    if x == 1 or x == n - 1:
        return True
    
    while p != n - 1:
        x = pow(x, 2, n)
        p *= 2
        if x == 1:
            return False
        elif x == n - 1:
            return True
    
    # n is not prime <=> False
    return False

# Prime check function => main
def isPrime(n):
    if n < 2:
        return False

    # list of lower primes to reduce unnecessary iterations
    list_Primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    # n is in the list of lower primes
    if n in list_Primes:
        return True

    # if low primes divide into n
    for prime in list_Primes:
        if n % prime == 0:
            return False
    
    # find number c such that c * 2 ^ r = n - 1
    c = n - 1 # c even bc n not divisible by 2
    while c % 2 == 0:
        c /= 2 # make c odd

    # test for not prime 130 times
    for i in range(130):
        if not MillerRabin(n,c):
            return False

    return True
def MakeKeys(size_key=1024):
    e = d = N = 0

    # generate p and q
    p = makePrimeNum(size_key)
    q = makePrimeNum(size_key)

    # RSA modulus
    N = p*q

    # The totient
    phiN = (p - 1)*(q - 1)
    
    # selection of key e
    while True:
        e = random.randrange(2 ** (size_key - 1), 2 ** size_key - 1)
        # e is coprime with phiN and 1 < e <= phiN
        if (isCoPrime(e, phiN)):
            break

    # choose d
    # d is mod inv of e with respect to phiN, e * d (mod phiN) = 1
    d = modularInv(e, phiN)

    return p, q, e, d, N, phiN

def makePrimeNum(size_key):
    # returns random large prime number of size_key bits in size

    while True:
        num = random.randrange(2**(size_key - 1), 2**size_key - 1)
        if (isPrime(num)):
            return num
        
def isCoPrime(p, q):
    # returns True if gcd(p,q) = 1 => p,q are relatively prime
    return gcd(p, q) == 1

def gcd(p, q):
    # iterative implementation of euclidean gcd
    while q:
        p, q = q, p % q
    return p

def egcd(a, b):
    s = 0
    s_0 = 1
    t = 1
    t_0 = 0
    r = b
    r_0 = a

    while r != 0:
        quotient = r_0 // r
        r_0, r = r, r_0-quotient*r
        s_0, s = s, s_0-quotient*s
        t_0, t = t, t_0-quotient*t

    # return gcd, x, y
    return r_0, s_0, t_0

def modularInv(a, b):
    x = egcd(a, b)[1]

    if x < 0:
        x += b

    return x

def encrypt(e, N, m):
    cipher = ""

    for x in m:
        msg = ord(x)
        cipher += str(pow(msg, e, N)) + " "

    return cipher

def decrypt(d, N, cipher):
    m = ""

    parts = cipher.split()
    for part in parts:
        if part:
            c = int(part)
            m += chr(pow(c, d, N))

    return m

def hash(a):
    hashed_msg = hashlib.sha256(str(a).encode()).hexdigest()
    hashed_msg_int = int(hashed_msg, 16)%N
    return str(hashed_msg_int)

def signature_verification(x,y):
    if x == y:
        return "Signature verified successfully"
    else:
        return "Signature verification failed"


if __name__ == "__main__":
    message = input("Input: ")
    print(message)
    size_key = 32

    p, q, e, d, N, phiN = MakeKeys(size_key)
    encrypted = encrypt(e, N, message)
    decrypted = decrypt(d, N, encrypted)
    encrypted_hash = encrypt(d,N,hash(message))
    decrypted_encrypted_hash = decrypt(e,N,encrypted_hash)
    print(signature_verification(hash(message),decrypted_encrypted_hash))

    print(f"Message: {message}")
    print(f"p: {p}")
    print(f"q: {q}")
    print(f"N: {N}")
    print(f"phiN: {phiN}")
    print(f"e: {e}")
    print(f"d: {d}")
    print(f"encrypted: {encrypted}")
    print(f"decrypted: {decrypted}")
