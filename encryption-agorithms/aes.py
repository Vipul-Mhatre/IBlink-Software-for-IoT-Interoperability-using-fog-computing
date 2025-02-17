import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_aes_key(key_size=32):
    return os.urandom(key_size)

def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding
    padded_message = message.encode() + b' ' * (16 - len(message.encode()) % 16)
    
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.rstrip().decode()

def measure_speed(message="Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!", iterations=10000):
    key = generate_aes_key()

    start = time.time()
    encrypted_data_list = []
    for _ in range(iterations):
        encrypted_data = aes_encrypt(message, key)
        encrypted_data_list.append(encrypted_data)
    encryption_time = time.time() - start

    start = time.time()
    for encrypted_data in encrypted_data_list:
        decrypted_message = aes_decrypt(encrypted_data, key)
    decryption_time = time.time() - start

    print("AES Encryption Algorithm Performance:")
    print(f"Encryption Time: {encryption_time:.6f} sec")
    print(f"Decryption Time: {decryption_time:.6f} sec")
    print(f"Total Time: {encryption_time + decryption_time:.6f} sec")

if __name__ == "__main__":
    measure_speed()
