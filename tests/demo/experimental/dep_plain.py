import sys
import math
import random


# def B(x, R):
#   return x - (4.0/ (27.0*pow(R,2)) )* pow(x,3)
#
# def P(y):
#   return y #identity
#   #return 1.0/(1.0+math.exp(-y)) #logistic
#
# def DEP1(x, L, R=1, n=1):
#   assert(n >= 1)
#   assert(x <= pow(L, n)*R and x >= -pow(L,n)*R)
#   y = x
#   for i in range(n-1, -1, -1):
#     assert(i >= 0)
#     y = pow(L, i)*B(y/pow(L,i), R)
#   return P(y)

def B(x):
  temp = x - (4/27)*x*x*x
  #print("Output after DEP1, B: ", temp)
  return temp

def P(y):
  return y #identity
  #return 1.0/(1.0+math.exp(-y)) #logistic

def DEP1(x, L, R=1, n=1):
  assert(n >= 1)
  assert(x <= pow(L, n)*R and x >= -pow(L,n)*R)
  y = x
  for i in range(n-1, -1, -1):
    assert(i >= 0)
    LtimesR = pow(L,i)*R
    invLR = 1 / LtimesR
    yMul_invR = y*invLR
    temp_y = B(yMul_invR)
    y = LtimesR * temp_y
    #print("Output after DEP func, y: ", y)
    #y = B(y*invLR)

  return P(y)

#Not currently in use - need to make Alg. 1 work first
def DEP2(x, L, R=1, n=1):
  assert(n >= 1)
  assert(x <= pow(L, n)*R and x >= -pow(L,n)*R)
  y = x
  for i in range(n-1, -1, -1):
    assert(i >= 0)
    y -= (4.0/(R*R*27*pow(L, 2*i))) * pow(y, 3)
    #y -= (4.0/(27*55*55))*y*y*y
  y /= R
  y += (4.0/27.0)*((L*L*(pow(L,n*2)-1))/((L*L-1)*pow(L,2*n)))*(pow(y,3) - pow(y,5))
  return P(R*y)

def main():
  L = 2.5
  n = 9
  R = 26
  min_val = 100
  max_val = 500000.0
  list_length = 8192
  offset = 4.0  # Offset to move the values outside the range -3 to 3
  print("Range is +-" + str(R*pow(L,n)))

  negative_vals = list(range(-99000, -2))

  # Generate values from 3 to 99000
  positive_vals = list(range(4, 99001))


  # Combine the two lists while keeping the range -3 to 3 excluded
  test_vals = negative_vals + positive_vals
  test_vals.append(0)
  dep_result = [DEP1(float(test_vals[i]), L, R, n) for i in range(len(test_vals))]

# Populate the list with random values ranging from -511758.0 to 511758.0,
# and then add an offset to move them outside the range -3 to 3.
  #test_vals = [random.uniform(min_val, max_val) + offset for _ in range(list_length)]
  # ========= test_vals = [float(i) for i in range(min_val, min_val + list_length)]
  # ========= dep_result = [DEP1(float(test_vals[i]), L, R, n) for i in range(8192)]

  # Print out the 20 smallest values in dep_result
  print("The 20 smallest values in dep_result:")
  for value in sorted(dep_result)[:20]:
      print(value, end=" ")
  print()

  is_within_range = any(-2 <= value <= 2 for value in dep_result)

  if is_within_range:
      print("At least one value in dep_result is between -3 and 3.")
  else:
      print("No value in dep_result is between -3 and 3.")

  values_in_range = [value for value in dep_result if -3 <= value <= 3]

# Print the values in the range -3 to 3
  print("The values in the range -3 to 3:")
  for value in values_in_range:
      print(value, end=" ")
  print()

  # print("Range is +-" + str(R*pow(L,n)))
  # for i in range(0,8192):
  #   n1 = DEP1(float(i), L=L, R=R, n=n)
  #   print(n1)
    # n2 = DEP1(n1, L=L, R=R, n=n)
    # print(n2)
    # n3 = DEP1(n2, L=L, R=R, n=n)
    # print(n3)



if __name__ == '__main__':
  main()
