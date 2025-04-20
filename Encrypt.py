import hashlib
import base64
import argparse
import os
from cryptography.fernet import Fernet

def generate_key(serial):
    hashed = hashlib.sha256(serial.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(hashed[:32])  # Valid Base64 encoding

parser = argparse.ArgumentParser(description="Encrypt a file using a dongle serial number.")
parser.add_argument("serial", help="The dongle serial number")
parser.add_argument("input_file", help="The path to the original file")

args = parser.parse_args()

key = generate_key(args.serial)
cipher = Fernet(key)

with open(args.input_file, "rb") as f:
    encrypted_data = cipher.encrypt(f.read())

output_file = args.input_file + ".enc"

with open(output_file, "wb") as f:
    f.write(encrypted_data)

print(f"file successfully encrypted and saved as {output_file}!")