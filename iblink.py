import os
import secrets
import hashlib
import struct
import numpy as np
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class OptimizediBlink:
    def __init__(self, security_level: int = 2048):
        """
        Optimized iBlink Cryptographic System for Fog Computing.
        This system:
        - Uses a hybrid encryption model
        - Implements an optimized prime caching system
        - Ensures efficient entropy collection
        """
        self.security_level = security_level
        self.prime_cache = []
        self.rsa_key_cache = None
        self.entropy_sources = self._collect_entropy()

    def _collect_entropy(self) -> bytes:
        """Optimized entropy collection for secure key generation."""
        sources = [
            struct.pack('d', secrets.SystemRandom().random()),  # System randomness
            os.urandom(32),  # OS randomness
            struct.pack('Q', os.getpid()),  # Process ID
            np.random.bytes(32)  # NumPy randomness
        ]
        return hashlib.shake_256(b''.join(sources)).digest(64)

    def _optimized_miller_rabin(self, n: int, k: int = 10) -> bool:
        """Miller-Rabin Primality Test for probabilistic prime validation."""
        if n <= 1 or n % 2 == 0:
            return n == 2  # Return True only for n=2

        small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small_primes:
            if n % p == 0:
                return n == p

        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(self) -> int:
        """Efficient prime generation with additional entropy."""
        if self.prime_cache:
            return self.prime_cache.pop()

        for _ in range(500):  # Increase attempts from 100 to 500
            candidate = int.from_bytes(
                hashlib.shake_256(os.urandom(64)).digest(self.security_level // 8),
                byteorder='big'
            ) | (1 << (self.security_level - 1)) | 1

            if self._optimized_miller_rabin(candidate, k=10):
                self.prime_cache.append(candidate)
                return candidate

        raise RuntimeError("Prime generation failed after multiple attempts")

    def generate_rsa_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair securely."""
        if self.rsa_key_cache:
            return self.rsa_key_cache

        p = self._generate_prime()
        q = self._generate_prime()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.security_level,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.rsa_key_cache = (private_key, public_key)
        return self.rsa_key_cache


class HybridEncryptor:
    @staticmethod
    def encrypt_data(data: bytes, public_key: rsa.RSAPublicKey) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using hybrid AES-GCM & RSA."""
        aes_key = os.urandom(32)
        nonce = os.urandom(12)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key, encrypted_data, encryptor.tag, nonce

    @staticmethod
    def decrypt_data(encrypted_aes_key: bytes, encrypted_data: bytes, tag: bytes, nonce: bytes,
                     private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt data using hybrid AES-GCM & RSA."""
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()


class FileHandler:
    @staticmethod
    def read_file(file_path: str) -> bytes:
        """Read file in binary mode."""
        with open(file_path, 'rb') as f:
            return f.read()

    @staticmethod
    def write_file(data: bytes, file_path: str):
        """Write file in binary mode."""
        with open(file_path, 'wb') as f:
            f.write(data)

    @staticmethod
    def process_encryption(input_path: str, output_path: str, public_key: rsa.RSAPublicKey):
        """Encrypt a file using hybrid encryption."""
        data = FileHandler.read_file(input_path)
        encrypted_aes_key, encrypted_data, tag, nonce = HybridEncryptor.encrypt_data(data, public_key)
        combined_data = encrypted_aes_key + tag + nonce + encrypted_data
        FileHandler.write_file(combined_data, output_path)
        print(f"File encrypted successfully: {output_path}")

    @staticmethod
    def process_decryption(input_path: str, output_path: str, private_key: rsa.RSAPrivateKey):
        """Decrypt a file using hybrid encryption."""
        combined_data = FileHandler.read_file(input_path)
        key_size = private_key.key_size // 8
        encrypted_aes_key = combined_data[:key_size]
        tag = combined_data[key_size:key_size + 16]
        nonce = combined_data[key_size + 16:key_size + 28]
        encrypted_data = combined_data[key_size + 28:]

        decrypted_data = HybridEncryptor.decrypt_data(encrypted_aes_key, encrypted_data, tag, nonce, private_key)
        FileHandler.write_file(decrypted_data, output_path)
        print(f"File decrypted successfully: {output_path}")


def main():
    """Main function to handle encryption and decryption."""
    crypto_system = OptimizediBlink(security_level=2048)

    print("Generating RSA Key Pair...")
    private_key, public_key = crypto_system.generate_rsa_keypair()
    print("RSA Key Pair Generated Successfully!")

    action = input("Choose action (encrypt/decrypt): ").lower()
    input_path = input("Enter file path: ")
    output_path = input("Enter output path: ")

    if action == 'encrypt':
        FileHandler.process_encryption(input_path, output_path, public_key)
    elif action == 'decrypt':
        FileHandler.process_decryption(input_path, output_path, private_key)
    else:
        print("Invalid action selected.")


if __name__ == "__main__":
    main()