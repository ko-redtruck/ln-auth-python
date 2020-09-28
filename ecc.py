from hashlib import sha256
from random import randint
import bech
#print(sha256("hello".encode()).hexdigest())


def hex_to_int(s):
    return int(s.replace(" ",""),base=16)

def extgcd(a, b):
    u, v, s, t = 1, 0, 0, 1
    while b!=0:
        q=a//b
        a, b = b, a-q*b
        u, s = s, u-q*s
        v, t = t, v-q*t
    return a, u, v

def modinverse(a, n):
    g, u, v=extgcd(a, n)
    return u%n

def sqrt(n, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist
    >>> assert (sqrt(n, q)[0] ** 2) % q == n
    >>> assert (sqrt(n, q)[1] ** 2) % q == n
    """
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")


class ecdsa:
    # m: message, d; key
    def sign(m,d,curve):
        e = int(sha256(m.encode()).hexdigest(),16)
        if e.bit_length()>curve.n.bit_length():
            z = e >> (e.bit_length() - curve.n.bit_length())
        else:
            z = e

        r,s=0,0

        while r == 0 or s == 0:

            k = randint(1,curve.n-1)

            p1 = curve.mul(curve.G,k)
            r = p1.x % curve.n

            s = ((z + r * d) * modinverse(k,curve.n)) % curve.n
        return r,s
    def verify(public_k, m, signature,curve):
        #normal ecdsa hashes the message but here k1 is the "hash" ??
        #e = int(sha256(m.encode()).hexdigest(),16)
        e = int(m,base=16)
        if e.bit_length()>curve.n.bit_length():
            z = e >> (e.bit_length() - curve.n.bit_length())
        else:
            z = e
        r,s = signature

        if r < 1 or r > curve.n -1:
            return False
        if s < 1 or s> curve.n -1:
            return False

        w = modinverse(s,curve.n)
        u1 = (z*w) % curve.n
        u2 = (r*w) % curve.n
        P = curve.add(curve.mul(curve.G,u1),curve.mul(public_k,u2))

        if (r % curve.n) == (P.x % curve.n):
            return True
        else:
            return False

    def compressed_to_point(c,curve):

        i = int(c[0:2],base=16)%2
        x = int(c[2:],base=16)

        z = (x**3 + curve.a*x + curve.b) % curve.p
        q = ((curve.p+1) * modinverse(4,curve.p)) % curve.p
        y_ = pow(z,q,curve.p)

        if i % 2 != 0:
            return point(x,curve.p-y_)
        else:
            return point(x,y_)
class elliptic_curve:
    def __init__(self,a,b,p,n=None,G=None):
        self.a = a
        self.b = b
        self.p = p

        self.n = n
        self.G = G

    def on_curve(self,P):
        return ((P.x**3 + self.a*P.x+ self.b) % self.p) == P.y*P.y


    #normal modulo does not work --> investigate why
    def add(self,p1,p2):

        if p1 == None:
            return p2

        if p2 == None:
            return p1

        if p1.x == p2.x and p1.y == p2.y:
            #k = ((3* (p1.x**2) + self.a )/ (2*p1.y)) % self.p
            k = (3* (p1.x**2) + self.a ) * modinverse(2*p1.y,self.p)
        else:
            #k = (p2.y - p1.y) * (p2.x-p1.x)**-1 % self.p
            k = (p2.y - p1.y) * modinverse(p2.x-p1.x,self.p)
        x = (k**2 - p1.x - p2.x) % self.p
        y = (k*(p1.x-x)-p1.y) % self.p

        return point(x,y)

    def mul(self,p1,n):
        R = None
        while n!=0:
            if n&1:
                R=self.add(R,p1)
            n=n>>1
            if (n!=0):
                p1 = self.add(p1,p1)
        return R

class point:
    def __init__(self,x,y):
        self.x = x
        self.y = y

    def __str__(self):
        return "x: "+hex(self.x)+" y: "+hex(self.y)


"""
#a, b, p, n, G

private_key = int(sha256("lol6f".encode()).hexdigest(),base=16)
print(hex(private_key))

#k1 = sha256("Hello World".encode()).hexdigest() #--> hex encoded 32 bytes of challenge

#k2 = sha256("n Worfd".encode()).hexdigest()

k1 = "lol"
k2 = "losl"
signature = ecdsa.sign(k1,private_key,scep256k1)
print(signature)




public_key = scep256k1.mul(scep256k1.G,private_key)
print(ecdsa.verify(public_key,k2,signature,scep256k1))
"""
G = point(
    hex_to_int("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798"),
    hex_to_int("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8")
)

scep256k1 = elliptic_curve(
    0,
    7,
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F"),
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"),
    G
)
k1 = "a198c68f27c55ea1bee5144fd0fd1dfc141870b64bfc8e79a59218d1781deb6c"
#print(len(k1))

private_key = int(sha256("lol6f".encode()).hexdigest(),base=16)
signature = ecdsa.sign(k1,private_key,scep256k1)
#print(signature)
public_key = scep256k1.mul(scep256k1.G,private_key)
print(ecdsa.verify(public_key,k1,signature,scep256k1))
print(ecdsa.compressed_to_point("0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267",scep256k1))
from der import decode_signature
der_sig = "30440220491552dae82c93fe3e3507bf6015104b5a7f90dd40c6e70b23d12bbfc79dcf0a02201a5b24c46182ff0d976eeb341f1e467b18aa00cd2205eebccecc275610c2fe91"
key = "0383fa6ab6d6e14d9f5a41a66f8188bddb364db89f8c72551c0266e16b86c6314c"
sig = decode_signature(der_sig)
print(sig)
p_key = ecdsa.compressed_to_point(key,scep256k1)
print(ecdsa.verify(p_key,k1,sig,scep256k1))
