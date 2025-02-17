import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def measure_speed(message="Hello Vipul Mhatre Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.!", iterations=100):
    private_key, public_key = generate_rsa_keys()

    start = time.time()
    encrypted_data_list = []
    for _ in range(iterations):
        encrypted_data = rsa_encrypt(message, public_key)
        encrypted_data_list.append(encrypted_data)
    encryption_time = time.time() - start

    start = time.time()
    for encrypted_data in encrypted_data_list:
        decrypted_message = rsa_decrypt(encrypted_data, private_key)
    decryption_time = time.time() - start

    print("RSA Encryption Algorithm Performance:")
    print(f"Encryption Time: {encryption_time:.6f} sec")
    print(f"Decryption Time: {decryption_time:.6f} sec")
    print(f"Total Time: {encryption_time + decryption_time:.6f} sec")

if __name__ == "__main__":
    measure_speed()
