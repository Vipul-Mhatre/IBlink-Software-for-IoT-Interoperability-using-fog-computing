import time
import os
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

def generate_blowfish_key(key_size=16):
    return os.urandom(key_size)

def blowfish_encrypt(message, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    padded_message = pad(message.encode(), Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return cipher.iv + ciphertext

def blowfish_decrypt(encrypted_data, key):
    iv = encrypted_data[:Blowfish.block_size]
    ciphertext = encrypted_data[Blowfish.block_size:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return decrypted_message.decode()

def measure_speed(message="Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!", iterations=10000):
    key = generate_blowfish_key()

    start = time.time()
    for _ in range(iterations):
        encrypted_data = blowfish_encrypt(message, key)
        decrypted_message = blowfish_decrypt(encrypted_data, key)
    total_time = time.time() - start

    print("Blowfish Encryption Algorithm Performance:")
    print(f"Total Time: {total_time:.6f} sec")
    print(f"Average Time per Operation: {total_time / (iterations * 2):.6f} sec")

if __name__ == "__main__":
    measure_speed()
