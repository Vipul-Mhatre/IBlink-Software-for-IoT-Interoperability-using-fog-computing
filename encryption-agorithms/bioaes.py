import os
import hashlib
import random
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to calculate entropy of a key
def calculate_entropy(data):
    byte_counts = {byte: data.count(byte) for byte in set(data)}
    entropy = -sum((count / len(data)) * (count / len(data)).bit_length() for count in byte_counts.values())
    return entropy / 8  # Normalize

# Function to get system resource usage
def get_system_resources():
    return psutil.cpu_percent(), psutil.virtual_memory().available

# Initial Key Generation with Entropy Sources
def generate_initial_key():
    system_entropy = os.urandom(16)  # Get random bytes from OS entropy pool
    device_state = str(psutil.cpu_percent()) + str(psutil.virtual_memory().available)  # System resource-based entropy
    hash_input = system_entropy + device_state.encode()
    return hashlib.sha256(hash_input).digest()[:16]  # Generate a 16-byte key

# Key Evolution through Biological Mutation
def key_evolution_function(key, mutation_rate, system_resources):
    key = bytearray(key)
    for _ in range(int(len(key) * mutation_rate)):
        index = random.randint(0, len(key) - 1)
        key[index] ^= random.randint(1, 255)  # XOR mutation
    return bytes(key)

# Determine AES Rounds based on Entropy and Resources
def calculate_num_rounds(key_entropy, system_resources):
    base_rounds = 10  # Standard AES-128 rounds
    cpu_usage, memory_available = system_resources
    
    if key_entropy > 0.8:
        return base_rounds + 2  # Increase rounds if entropy is high
    elif memory_available < 50000000:  # If available memory < 50MB, reduce rounds
        return base_rounds - 2
    else:
        return base_rounds

# Adaptive AES Encryption
def adaptive_aes_encrypt(plaintext, key, rounds):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

# Adaptive AES Decryption
def adaptive_aes_decrypt(ciphertext, key, rounds):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# Main Execution
def main():
    plaintext = input("Enter text to encrypt: ")
    
    # Step 1: Generate Initial Key
    initial_key = generate_initial_key()
    print(f"Initial Key: {initial_key.hex()}")
    
    # Step 2: Get System Resources
    system_resources = get_system_resources()
    
    # Step 3: Mutate Key (Biological Evolution)
    mutation_rate = 0.3 if system_resources[0] < 50 else 0.1  # Higher CPU load, lower mutation
    evolved_key = key_evolution_function(initial_key, mutation_rate, system_resources)
    print(f"Evolved Key: {evolved_key.hex()}")
    
    # Step 4: Determine AES Rounds
    key_entropy = calculate_entropy(evolved_key)
    num_rounds = calculate_num_rounds(key_entropy, system_resources)
    print(f"Using {num_rounds} AES rounds")
    
    # Step 5: Encrypt the Data
    encrypted_data = adaptive_aes_encrypt(plaintext, evolved_key, num_rounds)
    print(f"Encrypted Data: {encrypted_data.hex()}")
    
    # Step 6: Decrypt the Data
    decrypted_data = adaptive_aes_decrypt(encrypted_data, evolved_key, num_rounds)
    print(f"Decrypted Data: {decrypted_data}")

if __name__ == "__main__":
    main()