import random

def isPrime(n, k=5):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False

    return True

def factorize(n, b2=-1, b1=10000):
    def gcd(a, b):
        if b == 0:
            return a
        return gcd(b, a % b)

    def insertSorted(x, xs):
        i, ln = 0, len(xs)
        while i < ln and xs[i] < x:
            i += 1
        xs.insert(i, x)
        return xs

    if -1 <= n <= 1:
        return [n]
    if n < -1:
        return [-1] + factorize(-n)

    wheel = [1, 2, 2, 4, 2, 4, 2, 4, 6, 2, 6]
    w, f, fs = 0, 2, []

    while f * f <= n and f < b1:
        while n % f == 0:
            fs.append(f)
            n //= f
        f, w = f + wheel[w], w + 1
        if w == 11:
            w = 3

    if n == 1:
        return fs

    h, t, g, c = 1, 1, 1, 1

    while not isPrime(n):
        while b2 != 0 and g == 1:
            h = (h * h + c) % n
            h = (h * h + c) % n
            t = (t * t + c) % n
            g = gcd(t - h, n)
            b2 -= 1
        if b2 == 0:
            return fs
        if isPrime(g):
            while n % g == 0:
                fs = insertSorted(g, fs)
                n //= g
        h, t, g, c = 1, 1, 1, c + 1

    return insertSorted(n, fs)

def decrypt(ciphertext, factors, e):
    phi = 1
    for factor in factors:
        phi *= (factor - 1)
    d = pow(e, -1, phi)
    return pow(ciphertext, d, factors[0])

def main():
    # Input the public key (n, e) and ciphertext C
    n = int(input("Enter the value of n: "))
    e = int(input("Enter the value of e: "))
    ciphertext = int(input("Enter the ciphertext: "))

    # Factorize n
    factors = factorize(n)

    # Decrypt the ciphertext and find the original message
    message = decrypt(ciphertext, factors, e)
    print("Original message:", message)

# Run the main program
main()
