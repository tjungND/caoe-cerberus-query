import math

def test_func(x):
    return 1/x

def mapper(x, min_x, max_x, min_to, max_to):
    return (x - min_x) / (max_x - min_x) * (max_to - min_to) + min_to

def cheb_coef(func, n, min_val, max_val):
    coef = [0.0] * n
    for i in range(n):
        f = func(mapper(math.cos(math.pi * (i + 0.5) / n), -1, 1, min_val, max_val)) * 2 / n
        for j in range(n):
            coef[j] += f * math.cos(math.pi * j * (i + 0.5) / n)
    return coef

def cheb_approx(x, n, min_val, max_val, coef):
    a = 1
    b = mapper(x, min_val, max_val, -1, 1)
    c = float('nan')
    res = coef[0] / 2 + coef[1] * b

    x = 2 * b
    i = 2
    while i < n:
        c = x * b - a
        res = res + coef[i] * c
        (a, b) = (b, c)
        i += 1

    return res

def main():
    N = 10
    min_val = 0.0000000001
    max_val = 1073741824
    c = cheb_coef(test_func, N, min_val, max_val)

    print("Coefficients:")
    for i in range(N):
        print(" % lg" % c[i])

    print("\n\nApproximation:\n    x      func(x)       approx      diff")
    for i in range(20):
        x = mapper(i, 0.0, 20.0, min_val, max_val)
        f = test_func(x)
        approx = cheb_approx(x, N, min_val, max_val, c)
        print("%1.3f %10.10f %10.10f % 4.2e" % (x, f, approx, approx - f))

    return None

main()