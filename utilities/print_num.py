import sys

# Check if correct number of arguments are provided
if len(sys.argv) != 3:
    print("Usage: script_name.py x n")
    sys.exit(1)

# Try to convert arguments to integers
try:
    x = int(sys.argv[1])
    n = int(sys.argv[2])
except ValueError:
    print("Both x and n must be integers.")
    sys.exit(1)

# Check if n is positive
if n < 1:
    print("n must be positive.")
    sys.exit(1)

# Use a loop to print the numbers from x to x+n-1
for i in range(x, x + n):
    print(i)
