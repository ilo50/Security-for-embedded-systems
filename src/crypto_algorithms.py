from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os
import time

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

# 3. Symmetric Signatures - HMAC-SHA256
def hmac_keygen():
    key = os.urandom(32)
    return key, key

def hmac_sign(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_verify(key, signature, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(signature)

# 4. Hashing Implementations
def compute_sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# 5. Symmetric Encryption (Payload) - AES-GCM
def aes_gcm_keygen():
    return AESGCM.generate_key(bit_length=256)

def aes_gcm_encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def aes_gcm_decrypt(key, cipher_data):
    nonce = cipher_data[:12]
    ciphertext = cipher_data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)

# 6. Symmetric Encryption (Payload) - ChaCha20-Poly1305
def chacha20_keygen():
    return ChaCha20Poly1305.generate_key()

def chacha20_encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, data, None)

def chacha20_decrypt(key, cipher_data):
    nonce = cipher_data[:12]
    ciphertext = cipher_data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)

# 7. Benchmarking Utility
class BenchmarkTimer:
    def __init__(self, iterations=100):
        self.iterations = iterations
        self.total_flow_time = 0.0
        self.timings = {
            'identity_sign': {'time': 0.0, 'count': 0},
            'identity_verify': {'time': 0.0, 'count': 0},
            'payload_sign': {'time': 0.0, 'count': 0},
            'payload_verify': {'time': 0.0, 'count': 0},
            'hash': {'time': 0.0, 'count': 0},
            'decrypt': {'time': 0.0, 'count': 0},
            'encrypt': {'time': 0.0, 'count': 0}
        }
        
    def timed_op(self, func, category):
        def wrapper(*args):
            start = time.perf_counter()
            res = func(*args)
            self.timings[category]['time'] += (time.perf_counter() - start) * 1000
            self.timings[category]['count'] += 1
            return res
        return wrapper

    def add_flow_time(self, measured_time):
        self.total_flow_time += measured_time

    def get_avg(self, key):
        count = self.timings[key]['count']
        if count == 0: return 0.0
        return self.timings[key]['time'] / count
        
    def print_results(self, payload_size_kb):
        print(f"--- Flow Complete (Average over {self.iterations} runs) ---")
        print(f"Avg Total UpdateTime: {self.total_flow_time / self.iterations:.4f} ms")
        print(f"Avg Identity Sign Time:   {self.get_avg('identity_sign'):.4f} ms (~45 B)")
        print(f"Avg Identity Vrfy Time:   {self.get_avg('identity_verify'):.4f} ms (~45 B)")
        print(f"Avg Payload Sign Time:    {self.get_avg('payload_sign'):.4f} ms (~150 B)")
        print(f"Avg Payload Vrfy Time:    {self.get_avg('payload_verify'):.4f} ms (~150 B)")
        print(f"Avg Encrypting Time: {self.get_avg('encrypt'):.4f} ms ({payload_size_kb:.1f}KB)")
        print(f"Avg Decrypting Time: {self.get_avg('decrypt'):.4f} ms ({payload_size_kb:.1f}KB)")
        print(f"Avg Hashing Time:    {self.get_avg('hash'):.4f} ms ({payload_size_kb:.1f}KB)")
