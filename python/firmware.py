import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305

def benchmark_aead(name, cipher_obj, payload, iterations, has_nonce_length_param=False):
    # Warmup
    dummy_nonce = os.urandom(12)
    for _ in range(500):
        ct = cipher_obj.encrypt(dummy_nonce, payload, associated_data=None)
        cipher_obj.decrypt(dummy_nonce, ct, associated_data=None)

    total_enc_time = 0
    total_dec_time = 0

    for _ in range(iterations):
        # Most AEAD schemes prefer a 12-byte (96-bit) nonce
        nonce = os.urandom(12)
        
        start_enc = time.perf_counter()
        ciphertext = cipher_obj.encrypt(nonce, payload, associated_data=None)
        end_enc = time.perf_counter()
        
        start_dec = time.perf_counter()
        plaintext = cipher_obj.decrypt(nonce, ciphertext, associated_data=None)
        end_dec = time.perf_counter()

        total_enc_time += (end_enc - start_enc) * 1000
        total_dec_time += (end_dec - start_dec) * 1000

    print(f"\n--- {name} ---")
    print(f"Average Encryption time: {total_enc_time / iterations:.4f} ms")
    print(f"Average Decryption time: {total_dec_time / iterations:.4f} ms")


def main():
    blob_size = 100000
    firmware_blob = os.urandom(blob_size)
    iterations = 1000
    
    print(f"Benchmarking with payload size: {blob_size} bytes")

    # 1. AES-GCM (Galois/Counter Mode) - Very fast on modern CPUs with AES-NI instructions
    aes_gcm_key = AESGCM.generate_key(bit_length=256)
    benchmark_aead("AES-GCM (256-bit)", AESGCM(aes_gcm_key), firmware_blob, iterations)

    # 2. ChaCha20-Poly1305 - Faster on CPUs *without* AES-NI (e.g., older embedded devices, mobile)
    chacha_key = ChaCha20Poly1305.generate_key()
    benchmark_aead("ChaCha20-Poly1305", ChaCha20Poly1305(chacha_key), firmware_blob, iterations)

    # 3. AES-CCM (Counter with CBC-MAC) - Extremely common in embedded/IoT protocols (e.g., WiFi WPA2, Bluetooth LE)
    aes_ccm_key = AESCCM.generate_key(bit_length=256)
    benchmark_aead("AES-CCM (256-bit)", AESCCM(aes_ccm_key), firmware_blob, iterations)

if __name__ == "__main__":
    main()

