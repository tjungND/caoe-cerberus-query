

def poly(arg, coeffs, modulus=0):
  power = 1
  ret = 0
  for i in range(len(coeffs)):
    ret += coeffs[i] * power
    power *= arg
    if modulus:
      power %= modulus
      ret %= modulus
  return ret


num_coeffs = 15
coeffs = [i+1 for i in range(num_coeffs)]

arg = 3

print(poly(arg, coeffs, 536903681))
