import sys
import hashlib
import base64
import os
import tempfile
from cryptography.fernet import Fernet

def generate_key(serial):
    hashed = hashlib.sha256(serial.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def decrypt_file(serial, input_file, output_file=None, temp_mode=False):
    key = generate_key(serial)
    cipher = Fernet(key)
    
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    
    decrypted_data = cipher.decrypt(encrypted_data)
    
    if temp_mode:
        file_name, file_ext = os.path.splitext(os.path.basename(input_file).replace(".enc", ""))
        fd, temp_path = tempfile.mkstemp(suffix=file_ext, prefix=f"{file_name}_temp_")
        os.write(fd, decrypted_data)
        os.close(fd)
        return temp_path
    else:
        if output_file is None:
            file_name, file_ext = os.path.splitext(input_file.replace(".enc", ""))
            output_file = f"{file_name}_decrypted{file_ext}"
        
        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        
        print("\U0001F513 File decrypted successfully!")
        return output_file

def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <serial> <file> [--temp]")
        sys.exit(1)
    
    serial = sys.argv[1]
    input_file = sys.argv[2]
    temp_mode = "--temp" in sys.argv
    
    if temp_mode:
        temp_path = decrypt_file(serial, input_file, temp_mode=True)
        print(f"Temporary decrypted file created at: {temp_path}")
    else:
        file_name, file_ext = os.path.splitext(input_file.replace(".enc", ""))
        output_file = f"{file_name}_decrypted{file_ext}"
        decrypt_file(serial, input_file, output_file)

if __name__ == "__main__":
    main()