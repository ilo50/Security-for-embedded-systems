from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

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
