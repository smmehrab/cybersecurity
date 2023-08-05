import random

def isPrime(n, k=5):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
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


def factors(n, b2=-1, b1=10000):
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
        return [-1] + factors(-n)

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

print(factors(4155782502547623093831518113976094054382827573251453061239))
