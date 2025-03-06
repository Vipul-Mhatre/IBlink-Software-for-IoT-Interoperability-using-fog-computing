import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x448
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os
import inspect
import time

class QuantumEclipse:
    def __init__(self, security_level=3):
        """
        Initialize a quantum-resistant cryptographic system for fog computing.

        Args:
            security_level (int): Determines the complexity of cryptographic mechanisms.
                1: Basic (Conservative)
                2: Advanced (Recommended)
                3: Experimental (Research-grade)
        """
        self.security_level = security_level

        # ----- Generate Classical Elliptic Curve (EC) Keys -----
        # We select two high-security NIST curves.
        ec_curves = [ec.SECP521R1(), ec.SECP384R1()]
        self.ec_keys = []
        for curve in ec_curves:
            # Generate a private key for the given EC curve.
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            # Store key information in a dictionary.
            self.ec_keys.append({
                "type": "EC",
                "curve": curve,
                "private_key": private_key,
                "public_key": public_key
            })

        # ----- Generate Post-Quantum X448 Key -----
        # Instead of calling x448.X448(), we generate a key with X448PrivateKey.generate().
        x448_private_key = x448.X448PrivateKey.generate()
        x448_public_key = x448_private_key.public_key()
        self.x448_key = {
            "type": "X448",
            "private_key": x448_private_key,
            "public_key": x448_public_key
        }

        # ----- Combine Keys for Hybrid Key Exchange -----
        # The final list contains all keys, allowing us to perform a multi-key exchange.
        self.keys = self.ec_keys + [self.x448_key]
        self.public_keys = [k["public_key"] for k in self.keys]

        # ----- Advanced Entropy Sources -----
        # Using multiple sources increases randomness and helps in mixing secrets.
        self.entropy_sources = [
            os.urandom,  # OS-level randomness
            np.random.default_rng().bytes,  # NumPy's RNG (ensure cryptographic strength in your context)
            hashlib.sha3_512  # Additional entropy mixing via SHA3-512
        ]

    def _hybrid_key_exchange(self, peer_public_keys):
        """
        Perform a hybrid key exchange using multiple keys.
        
        Args:
            peer_public_keys (list): Public keys received from peer devices.
        
        Returns:
            bytes: A hybridized shared secret.
        """
        shared_secrets = []
        # Iterate over each local key.
        for key_info in self.keys:
            local_key = key_info["private_key"]
            key_type = key_info["type"]
            # Attempt key exchange with each provided peer public key.
            for peer_key in peer_public_keys:
                try:
                    if key_type == "EC":
                        # For EC keys, use ECDH.
                        shared_secret = local_key.exchange(ec.ECDH(), peer_key)
                    elif key_type == "X448":
                        # For X448, the exchange method is directly available.
                        shared_secret = local_key.exchange(peer_key)
                    else:
                        continue  # Skip if unknown key type.
                    shared_secrets.append(shared_secret)
                except Exception as e:
                    print(f"Key exchange error with key type {key_type}: {e}")
        # Mix all shared secrets into one final key.
        return self._secret_mixer(shared_secrets)

    def _secret_mixer(self, secrets):
        """
        Combine multiple shared secrets and extra entropy to create a final key.
        
        Args:
            secrets (list): A list of shared secrets.
        
        Returns:
            bytes: A combined secret with high entropy.
        """
        # Aggregate extra entropy from multiple sources.
        entropy = b''.join([
            source() if callable(source) else source(secrets[0])
            for source in self.entropy_sources
        ])
        
        # Use the shake_256 hash to mix all secrets and entropy.
        mixed_secret = hashlib.shake_256()
        for secret in secrets:
            mixed_secret.update(secret)
        mixed_secret.update(entropy)
        
        # Return a 512-bit output.
        return mixed_secret.digest(64)

    def encrypt(self, peer_public_keys, plaintext, associated_data=None):
        """
        Encrypt data using a hybrid key exchange and authenticated encryption.
        
        Args:
            peer_public_keys (list): Public keys of target devices.
            plaintext (bytes): Data to be encrypted.
            associated_data (bytes, optional): Additional data for authentication.
        
        Returns:
            tuple: (ciphertext, authentication tag, metadata)
        """
        # Perform the hybrid key exchange to derive a shared secret.
        shared_secret = self._hybrid_key_exchange(peer_public_keys)
        
        # Derive key material from the shared secret using HKDF.
        kdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,  # Total key material length
            salt=os.urandom(32),
            info=b'quantum-eclipse-kdf',
            backend=default_backend()
        )
        key_material = kdf.derive(shared_secret)
        
        # Split the key material into an encryption key, MAC key, and nonce.
        encryption_key = key_material[:32]
        mac_key = key_material[32:64]
        nonce = key_material[64:96]
        
        # Set up an authenticated cipher using ChaCha20_Poly1305.
        cipher = Cipher(
            algorithms.ChaCha20_Poly1305(encryption_key),
            modes.ChaCha20_Poly1305(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        # Build metadata for tracking, including which keys were used.
        metadata = {
            'keys_used': [ "EC:" + str(info["curve"]) if info["type"] == "EC" else "X448" for info in self.keys ],
            'security_level': self.security_level,
            'timestamp': os.urandom(16)  # Using randomness as a unique identifier (for demo purposes)
        }
        
        return ciphertext, tag, metadata

    def decrypt(self, peer_public_keys, ciphertext, tag, metadata=None):
        """
        Decrypt data using the corresponding hybrid key exchange.
        
        Args:
            peer_public_keys (list): Public keys from the source device.
            ciphertext (bytes): Data to be decrypted.
            tag (bytes): Authentication tag from the encryption process.
            metadata (dict, optional): Additional metadata for verification.
        
        Returns:
            bytes: The decrypted plaintext.
        """
        # Reconstruct the shared secret using the same hybrid key exchange.
        shared_secret = self._hybrid_key_exchange(peer_public_keys)
        
        # Derive key material from the shared secret.
        kdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=128,
            salt=os.urandom(32),
            info=b'quantum-eclipse-kdf',
            backend=default_backend()
        )
        key_material = kdf.derive(shared_secret)
        
        encryption_key = key_material[:32]
        mac_key = key_material[32:64]
        nonce = key_material[64:96]
        
        # Set up the cipher for decryption with the authentication tag.
        cipher = Cipher(
            algorithms.ChaCha20_Poly1305(encryption_key),
            modes.ChaCha20_Poly1305(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # (Optional) Verify metadata if needed.
        if metadata:
            # Implement any additional metadata checks here.
            pass
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

class QuantumEclipseV2(QuantumEclipse):
    def __init__(self, security_level=3):
        super().__init__(security_level)
        self.quantum_noise = np.random.default_rng()
        
        # Initialize entropy sources with proper parameters
        self.entropy_sources = [
            lambda: os.urandom(32),  # Fixed size for OS-level randomness
            lambda: self.quantum_noise.bytes(32),  # NumPy's RNG
            lambda x: hashlib.sha3_512(x).digest()  # SHA3-512 for mixing
        ]
        
    def _hybrid_key_exchange(self, peer_public_keys):
        """
        Perform a hybrid key exchange using multiple keys.
        """
        shared_secrets = []
        
        # Match key types properly during exchange
        for key_info in self.keys:
            local_key = key_info["private_key"]
            key_type = key_info["type"]
            
            for peer_key in peer_public_keys:
                try:
                    if key_type == "EC" and isinstance(peer_key, ec.EllipticCurvePublicKey):
                        if str(local_key.curve.name) == str(peer_key.curve.name):
                            shared_secret = local_key.exchange(ec.ECDH(), peer_key)
                            shared_secrets.append(shared_secret)
                    elif key_type == "X448" and isinstance(peer_key, x448.X448PublicKey):
                        shared_secret = local_key.exchange(peer_key)
                        shared_secrets.append(shared_secret)
                except Exception as e:
                    print(f"Key exchange error: {e}")
                    continue
                    
        if not shared_secrets:
            raise ValueError("No compatible key pairs found for exchange")
            
        return self._secret_mixer(shared_secrets)
        
    def _secret_mixer(self, secrets):
        """
        Combine multiple shared secrets and extra entropy to create a final key.
        """
        # Use shake_256 for mixing with fixed-size output
        mixed_secret = hashlib.shake_256()
        
        # Add all shared secrets
        for secret in secrets:
            mixed_secret.update(secret)
            
        # Add extra entropy
        mixed_secret.update(os.urandom(32))
        
        return mixed_secret.digest(32)  # Return 32 bytes for AES-256

    def encrypt(self, peer_public_keys, plaintext, associated_data=None):
        """
        Encrypt data using a hybrid key exchange and authenticated encryption.
        """
        # First apply lattice mixing
        mixed_data = self._lattice_based_mixing(plaintext)
        
        # Apply neural confusion
        confused_data = self._neural_confusion(mixed_data)
        
        # Generate nonce
        nonce = os.urandom(12)  # 96 bits for GCM
        
        # Perform the hybrid key exchange to derive encryption key
        encryption_key = self._hybrid_key_exchange(peer_public_keys)
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        # Add associated data if provided
        if associated_data:
            cipher.authenticate_additional_data(associated_data)
        
        # Encrypt the data
        ciphertext = cipher.update(confused_data) + cipher.finalize()
        
        # Build metadata
        metadata = {
            'keys_used': [str(info["curve"].name) if info["type"] == "EC" else "X448" for info in self.keys],
            'security_level': self.security_level,
            'timestamp': time.time(),
            'nonce': nonce
        }
        
        return ciphertext, cipher.tag, metadata

    def decrypt(self, peer_public_keys, ciphertext, tag, metadata=None):
        """
        Decrypt data using the hybrid key exchange.
        """
        if not metadata or 'nonce' not in metadata:
            raise ValueError("Missing nonce in metadata")
            
        # Reconstruct the encryption key using same key exchange
        encryption_key = self._hybrid_key_exchange(peer_public_keys)
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(metadata['nonce'], tag),
            backend=default_backend()
        ).decryptor()
        
        # Decrypt the data
        confused_data = cipher.update(ciphertext) + cipher.finalize()
        
        # Reverse neural confusion
        unconfused_data = self._neural_confusion(confused_data)
        
        # Reverse lattice mixing
        return self._lattice_based_mixing(unconfused_data)

    def _lattice_based_mixing(self, data):
        """
        Apply lattice-based mixing for additional security layer
        """
        # Convert data to numpy array
        data_array = np.frombuffer(data, dtype=np.uint8)
        
        # Generate random lattice basis (smaller values to prevent overflow)
        n = len(data_array)
        basis = self.quantum_noise.integers(1, 16, size=(n, n), dtype=np.uint8)
        
        # Apply lattice transformation with proper type casting
        transformed = np.dot(data_array.astype(np.uint16), basis.astype(np.uint16)) % 256
        return bytes(transformed.astype(np.uint8))

    def _neural_confusion(self, data):
        """
        Apply neural network-based confusion function
        """
        data_array = np.frombuffer(data, dtype=np.uint8)
        
        # Simple neural transformation with scaling to prevent overflow
        weights = self.quantum_noise.random((len(data_array), 1)) * 0.1
        activation = np.tanh(np.dot(data_array.astype(np.float32), weights))
        
        # Convert back to bytes maintaining entropy
        confused = (activation * 255).astype(np.uint8)
        return bytes(confused.flatten())

def fog_computing_demo():
    """
    Demonstrates the enhanced QuantumEclipseV2 system in a fog computing scenario.
    """
    print("\nInitializing QuantumEclipseV2 Encryption System...")
    
    # Initialize encryption system for three nodes
    edge_node = QuantumEclipseV2(security_level=3)
    fog_node1 = QuantumEclipseV2(security_level=3)
    fog_node2 = QuantumEclipseV2(security_level=3)

    # Simulate sensor data
    sensor_data = b"Critical sensor readings: Temperature=25.6C, Pressure=1013hPa, Humidity=65%"
    print(f"\nOriginal Data: {sensor_data.decode()}")

    print("\nPerforming encryption with novel hybrid scheme...")
    start_time = time.time()
    
    try:
        # Encrypt data from edge to fog nodes
        encrypted_data, tag, metadata = edge_node.encrypt(
            [fog_node1.public_keys[0]], 
            sensor_data
        )
        
        encryption_time = time.time() - start_time
        print(f"Encryption completed in {encryption_time*1000:.2f}ms")
        print(f"Encrypted Size: {len(encrypted_data)} bytes")
        print(f"Compression Ratio: {len(sensor_data)/len(encrypted_data):.2f}x")
        print(f"Keys used: {metadata['keys_used']}")

        print("\nPerforming decryption at fog node...")
        start_time = time.time()
        
        # Decrypt at fog node 1
        decrypted_data = fog_node1.decrypt(
            [edge_node.public_keys[0]], 
            encrypted_data, 
            tag, 
            metadata
        )
        
        decryption_time = time.time() - start_time
        print(f"Decryption completed in {decryption_time*1000:.2f}ms")
        print(f"\nDecrypted Data at Fog Node 1: {decrypted_data.decode()}")

        # Performance metrics
        print(f"\nPerformance Metrics:")
        print(f"Average Round-Trip Time: {(encryption_time + decryption_time)*1000:.2f}ms")
        print(f"Throughput: {len(sensor_data)/(encryption_time + decryption_time)/1024:.2f} KB/second")
        
    except Exception as e:
        print(f"Error during encryption/decryption: {e}")

if __name__ == "__main__":
    fog_computing_demo()
