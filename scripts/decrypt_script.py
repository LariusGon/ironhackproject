import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

def decrypt_file(file_path: str, key: bytes):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        data = decrypt_data(key, encrypted_data)
        decrypted_file_path = os.path.splitext(file_path)[0]  # Remove .enc extension
        with open(decrypted_file_path, 'wb') as f:
            f.write(data)
        print(f"File decrypted: {decrypted_file_path}")
        return True
    except IOError as e:
        print(f"IO Error decrypting file {file_path}: {e}")
    except Exception as e:
        print(f"Unexpected error decrypting file {file_path}: {e}")
    return False

def process_folder(folder_path: str, key: bytes):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.enc'):
                if decrypt_file(file_path, key):
                    os.remove(file_path)

def main():
    folder_paths = input("Enter folder paths to decrypt (comma-separated): ").split(',')
    password = getpass("Enter decryption password: ")
    
    salt_file = 'encryption_salt.bin'
    try:
        with open(salt_file, 'rb') as f:
            salt = f.read()
    except FileNotFoundError:
        print(f"Salt file '{salt_file}' not found. Cannot proceed with decryption.")
        return

    key = derive_key(password, salt)
    
    for folder_path in folder_paths:
        folder_path = folder_path.strip()
        if not os.path.isdir(folder_path):
            print(f"Invalid folder path: {folder_path}")
            continue
        process_folder(folder_path, key)
    
    print("Decryption completed.")

if __name__ == "__main__":
    main()