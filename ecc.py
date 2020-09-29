from hashlib import sha256
from random import randint

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

    def verify(public_k,m,signature,curve):
        return ecdsa.raw_verify(public_k,sha256(m.encode()).hexdigest(),signature,curve)

    def raw_verify(public_k, h, signature,curve):
        e = int(h,base=16)
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


    def add(self,p1,p2):

        if p1 == None:
            return p2

        if p2 == None:
            return p1

        if p1.x == p2.x and p1.y == p2.y:
            k = (3* (p1.x**2) + self.a ) * modinverse(2*p1.y,self.p)
        else:
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
