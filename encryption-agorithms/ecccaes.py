import time
import os
import hashlib
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_ecc_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.verifying_key
    return private_key, public_key

def compute_shared_secret(private_key, public_key):

    shared_point = private_key.privkey.secret_multiplier * public_key.pubkey.point
    
    point_bytes = str(shared_point.x()).encode() + str(shared_point.y()).encode()
    
    shared_key = hashlib.sha3_256(point_bytes).digest()
    return shared_key

def iblink_encrypt(message, private_key, public_key):
    shared_key = compute_shared_secret(private_key, public_key)
    aes_key = shared_key[:16]  # Use first 16 bytes for AES key

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # Generate a random nonce
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    print(f"Encryption Shared Key: {shared_key.hex()}")
    print(f"Encryption AES Key: {aes_key.hex()}")
    print(f"Nonce: {nonce.hex()}")

    return nonce + ciphertext  # Return nonce + encrypted data

def iblink_decrypt(encrypted_data, private_key, public_key):
    shared_key = compute_shared_secret(private_key, public_key)
    aes_key = shared_key[:16]  # Use first 16 bytes for AES key

    aesgcm = AESGCM(aes_key)
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]  # Ensure correct split

    print(f"Decryption Shared Key: {shared_key.hex()}")
    print(f"Decryption AES Key: {aes_key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Ciphertext Length: {len(ciphertext)}")

    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def standard_ecc_encrypt(message, private_key, public_key):
    return compute_shared_secret(private_key, public_key)  # Just Key Exchange

def measure_speed():
    message = "Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!"
    pi_private, pi_public = generate_ecc_keys()
    cloud_private, cloud_public = generate_ecc_keys()

    start = time.time()
    for _ in range(1000):
        standard_ecc_encrypt(message, pi_private, cloud_public)
    standard_time = time.time() - start

    start = time.time()
    for _ in range(1000):
        iblink_encrypt(message, pi_private, cloud_public)
    iblink_time = time.time() - start

    print(f"Standard ECC Time: {standard_time:.6f} sec")
    print(f"iblink Time: {iblink_time:.6f} sec")
    print(f"Speed Improvement: {standard_time / iblink_time:.2f}x faster")

def test_iblink():
    message = "Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!"
    
    pi_private, pi_public = generate_ecc_keys()
    cloud_private, cloud_public = generate_ecc_keys()

    encrypted_data = iblink_encrypt(message, pi_private, cloud_public)
    print(f"Encrypted: {encrypted_data.hex()}")

    decrypted_message = iblink_decrypt(encrypted_data, cloud_private, pi_public)
    print(f"Decrypted: {decrypted_message}")

test_iblink()
measure_speed()