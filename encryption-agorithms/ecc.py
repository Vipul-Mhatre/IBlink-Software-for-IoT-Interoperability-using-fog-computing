import time
import os
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ECCCrypto:
    @staticmethod
    def generate_keys(curve=ec.SECP256R1()):
        private_key = ec.generate_private_key(curve, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def compute_shared_secret(private_key, public_key):
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        return shared_key

    @staticmethod
    def derive_key(shared_secret, salt=None, info=b'ecc-encryption'):
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
    def encrypt(message, private_key, public_key):
        shared_secret = ECCCrypto.compute_shared_secret(private_key, public_key)
        derived_key, salt = ECCCrypto.derive_key(shared_secret)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return salt + iv + ciphertext

    @staticmethod
    def decrypt(encrypted_data, private_key, public_key):
        shared_secret = ECCCrypto.compute_shared_secret(private_key, public_key)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        derived_key, _ = ECCCrypto.derive_key(shared_secret, salt)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def measure_performance(message="Secure Communication", iterations=10000):
    sender_private, sender_public = ECCCrypto.generate_keys()
    receiver_private, receiver_public = ECCCrypto.generate_keys()

    start_encryption = time.time()
    encrypted_data_list = []
    for _ in range(iterations):
        encrypted_data = ECCCrypto.encrypt(message, sender_private, receiver_public)
        encrypted_data_list.append(encrypted_data)
    encryption_time = time.time() - start_encryption

    start_decryption = time.time()
    decrypted_messages = []
    for encrypted_data in encrypted_data_list:
        decrypted_message = ECCCrypto.decrypt(encrypted_data, receiver_private, sender_public)
        decrypted_messages.append(decrypted_message)
    decryption_time = time.time() - start_decryption

    total_time = encryption_time + decryption_time

    print("🔒 ECC Encryption Performance:")
    print(f"Encryption Time: {encryption_time:.6f} sec")
    print(f"Decryption Time: {decryption_time:.6f} sec")
    print(f"Total Time: {total_time:.6f} sec")
    print(f"Average Time per Operation: {total_time / (iterations * 2):.6f} sec")
    
    return {
        'encryption_time': encryption_time,
        'decryption_time': decryption_time,
        'total_time': total_time
    }

if __name__ == "__main__":
    measure_performance()
