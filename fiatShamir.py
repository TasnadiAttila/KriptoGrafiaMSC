import sympy
import secrets

p = sympy.randprime(1, 100000)
q = sympy.randprime(1, 100000)
n = p * q

x = secrets.randbelow(n - 1)
y = (x ** 2) % n

for i in range(10):
    r = secrets.randbelow(n - 1)
    t = (r ** 2) % n

    c = secrets.choice([0, 1])

    s = (r * (x ** c)) % n

    left_side = (s ** 2) % n
    right_side = (t * (y ** c)) % n

    print(f'P igazolta magát a(z) {i + 1}. körben: {"Igen" if left_side == right_side else "Nem"}')
