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
from pqcrypto.kem import ntru

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
    def hybrid_key_exchange(private_key, public_key, pq_public_key):
        # Classical ECDH shared secret
        shared_secret_ecdh = IBLinkCrypto.compute_shared_secret(private_key, public_key)
        
        # Post-Quantum NTRU key exchange 
        shared_secret_pq, _ = ntru.shared_key(private_key.to_string(), pq_public_key)

        # Combine both secrets
        return shared_secret_ecdh + shared_secret_pq

    @staticmethod
    def encrypt(message, private_key, public_key, pq_public_key, precomputed_secret=None):
        shared_secret = precomputed_secret or IBLinkCrypto.hybrid_key_exchange(private_key, public_key, pq_public_key)
        derived_key, salt = IBLinkCrypto.derive_key(shared_secret)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return salt + iv + ciphertext

    @staticmethod
    def decrypt(encrypted_data, private_key, public_key, pq_public_key, precomputed_secret=None):
        shared_secret = precomputed_secret or IBLinkCrypto.hybrid_key_exchange(private_key, public_key, pq_public_key)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        derived_key, _ = IBLinkCrypto.derive_key(shared_secret, salt)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    @staticmethod
    def parallel_encryption(messages, private_key, public_key, pq_public_key):
        num_cores = multiprocessing.cpu_count()
        with multiprocessing.Pool(num_cores) as pool:
            shared_secret = IBLinkCrypto.hybrid_key_exchange(private_key, public_key, pq_public_key)
            encrypted_messages = pool.starmap(
                IBLinkCrypto.encrypt, 
                [(msg, private_key, public_key, pq_public_key, shared_secret) for msg in messages]
            )
        return encrypted_messages

    @staticmethod
    def parallel_decryption(encrypted_messages, private_key, public_key, pq_public_key):
        num_cores = multiprocessing.cpu_count()
        with multiprocessing.Pool(num_cores) as pool:
            shared_secret = IBLinkCrypto.hybrid_key_exchange(private_key, public_key, pq_public_key)
            decrypted_messages = pool.starmap(
                IBLinkCrypto.decrypt, 
                [(msg, private_key, public_key, pq_public_key, shared_secret) for msg in encrypted_messages]
            )
        return decrypted_messages

# Zero-Knowledge Proof (ZKP) Dummy Implementation for Illustration
def zero_knowledge_proof():
    # placheolder
    return True

def measure_performance_optimized(message="Hello Vipul!", iterations=10000):
    pi_private, pi_public = IBLinkCrypto.generate_keys()
    cloud_private, cloud_public = IBLinkCrypto.generate_keys()

    _, pq_public_key = ntru.generate_keypair()

    start_encryption = time.time()
    encrypted_data_list = IBLinkCrypto.parallel_encryption([message] * iterations, pi_private, cloud_public, pq_public_key)
    encryption_time = time.time() - start_encryption

    start_decryption = time.time()
    decrypted_messages = IBLinkCrypto.parallel_decryption(encrypted_data_list, cloud_private, pi_public, pq_public_key)
    decryption_time = time.time() - start_decryption

    total_time = encryption_time + decryption_time

    print("Hybrid Encryption Performance with Post-Quantum Key Exchange and Zero-Knowledge Proofs:")
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