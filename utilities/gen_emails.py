import sys
import random
import string

def generate_fake_email():
    domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "protonmail.com", "mail.com"]
    name_length = random.randint(5, 10)
    name = ''.join(random.choice(string.ascii_lowercase) for _ in range(name_length))
    domain = random.choice(domains)
    return f"{name}.{random.choice(string.ascii_lowercase)}@{domain}"

num_lines = 10000

if len(sys.argv) < 2:
    print("Usage: python script_name.py <file_name>")
    sys.exit(1)

file_name = sys.argv[1]
if len(sys.argv) >= 3:
    num_lines = int(sys.argv[2])

with open(file_name, "w") as file:
    for i in range(num_lines):
        fake_email = generate_fake_email()
        file.write(f"{i} {fake_email}\n")

print(f"Generated {num_lines} fake email addresses and saved them in '{file_name}'.")

