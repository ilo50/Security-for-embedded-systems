from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os

# 1. Ed25519 Implementations
def ed25519_keygen():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def ed25519_sign(priv, data):
    return priv.sign(data)

def ed25519_verify(pub, sig, data):
    pub.verify(sig, data)

# 2. RSA 2048 Implementations
def rsa_keygen():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def rsa_sign(priv, data):
    return priv.sign(
        data, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
        hashes.SHA256()
    )

def rsa_verify(pub, sig, data):
    pub.verify(
        sig, 
        data, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
        hashes.SHA256()
    )

# 3. Hashing Implementations
def compute_sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# 4. Symmetric Encryption (Payload) - AES-GCM
def aes_gcm_keygen():
    return AESGCM.generate_key(bit_length=256)

def aes_gcm_encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def aes_gcm_decrypt(key, cipher_data):
    nonce = cipher_data[:12]
    ciphertext = cipher_data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

# 5. Symmetric Encryption (Payload) - ChaCha20-Poly1305
def chacha20_keygen():
    return ChaCha20Poly1305.generate_key()

def chacha20_encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, data, None)

def chacha20_decrypt(key, cipher_data):
    nonce = cipher_data[:12]
    ciphertext = cipher_data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
