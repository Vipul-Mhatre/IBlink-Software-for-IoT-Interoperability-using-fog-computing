import time
import os
import hashlib
import multiprocessing
from functools import lru_cache
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class IBLinkCrypto:
    @staticmethod
    @lru_cache(maxsize=128)
    def generate_keys(curve=SECP256k1):
        private_key = SigningKey.generate(curve=curve)
        public_key = private_key.verifying_key
        return private_key, public_key

    @staticmethod
    @lru_cache(maxsize=256)
    def derive_key(shared_secret, salt=None, info=b'iblink-encryption'):
        if salt is None:
            salt = os.urandom(16)
        
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret), salt

    @staticmethod
    def compute_shared_secret(private_key, public_key):
        shared_point = private_key.privkey.secret_multiplier * public_key.pubkey.point
        return str(shared_point.x()).encode() + str(shared_point.y()).encode()

    @staticmethod
    def encrypt(message, private_key, public_key, precomputed_secret=None):
        shared_secret = precomputed_secret or IBLinkCrypto.compute_shared_secret(private_key, public_key)
        derived_key, salt = IBLinkCrypto.derive_key(shared_secret)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return salt + iv + ciphertext

    @staticmethod
    def decrypt(encrypted_data, private_key, public_key, precomputed_secret=None):
        shared_secret = precomputed_secret or IBLinkCrypto.compute_shared_secret(private_key, public_key)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        derived_key, _ = IBLinkCrypto.derive_key(shared_secret, salt)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    @staticmethod
    def parallel_encryption(messages, private_key, public_key):
        num_cores = multiprocessing.cpu_count()
        with multiprocessing.Pool(num_cores) as pool:
            shared_secret = IBLinkCrypto.compute_shared_secret(private_key, public_key)
            encrypted_messages = pool.starmap(
                IBLinkCrypto.encrypt, 
                [(msg, private_key, public_key, shared_secret) for msg in messages]
            )
        return encrypted_messages

    @staticmethod
    def parallel_decryption(encrypted_messages, private_key, public_key):
        num_cores = multiprocessing.cpu_count()
        with multiprocessing.Pool(num_cores) as pool:
            shared_secret = IBLinkCrypto.compute_shared_secret(private_key, public_key)
            decrypted_messages = pool.starmap(
                IBLinkCrypto.decrypt, 
                [(msg, private_key, public_key, shared_secret) for msg in encrypted_messages]
            )
        return decrypted_messages

def measure_performance_optimized(message="Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!", iterations=10000):
    pi_private, pi_public = IBLinkCrypto.generate_keys()
    cloud_private, cloud_public = IBLinkCrypto.generate_keys()

    shared_secret = IBLinkCrypto.compute_shared_secret(pi_private, cloud_public)

    start_encryption = time.time()
    encrypted_data_list = IBLinkCrypto.parallel_encryption([message] * iterations, pi_private, cloud_public)
    encryption_time = time.time() - start_encryption

    start_decryption = time.time()
    decrypted_messages = IBLinkCrypto.parallel_decryption(encrypted_data_list, cloud_private, pi_public)
    decryption_time = time.time() - start_decryption

    total_time = encryption_time + decryption_time

    print(" IBLink Encryption Performance :")
    print(f"Encryption Time: {encryption_time:.6f} sec")
    print(f"Decryption Time: {decryption_time:.6f} sec")
    print(f"Total Time: {total_time:.6f} sec")
    print(f"Average Time per Operation: {total_time / (iterations * 2):.6f} sec")
    
    return {
        'encryption_time': encryption_time,
        'decryption_time': decryption_time,
        'total_time': total_time
    }

def benchmark_comparison(message="Secure Communication", iterations=10000):
    
    iblink_perf = measure_performance_optimized(message, iterations)
    
if __name__ == "__main__":
    benchmark_comparison()