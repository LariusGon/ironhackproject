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

def encrypt_data(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def encrypt_file(file_path: str, key: bytes):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = encrypt_data(key, data)
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        print(f"File encrypted: {encrypted_file_path}")
        return True
    except IOError as e:
        print(f"IO Error encrypting file {file_path}: {e}")
    except Exception as e:
        print(f"Unexpected error encrypting file {file_path}: {e}")
    return False

def process_folder(folder_path: str, key: bytes):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if not file.endswith('.enc'):
                if encrypt_file(file_path, key):
                    os.remove(file_path)

def main():
    folder_paths = input("Enter folder paths to encrypt (comma-separated): ").split(',')
    password = getpass("Enter encryption password: ")
    
    salt_file = 'encryption_salt.bin'
    salt = os.urandom(16)
    with open(salt_file, 'wb') as f:
        f.write(salt)

    key = derive_key(password, salt)
    
    for folder_path in folder_paths:
        folder_path = folder_path.strip()
        if not os.path.isdir(folder_path):
            print(f"Invalid folder path: {folder_path}")
            continue
        process_folder(folder_path, key)
    
    print("Encryption completed.")

if __name__ == "__main__":
    main()