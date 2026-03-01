import time
from director_repo import DirectorRepository
from image_repo import ImageRepository
from vehicle_ecu import VehicleECU
import crypto_algorithms as crypto

def run_benchmark(sign_label, hash_label, enc_label, key_gen_func, sign_func, verify_func, hash_func, sym_key_gen, encrypt_func, decrypt_func, iterations=100, debug=False):
    """Orchestrates the modular components, showing the Uptane pipeline and timing it."""
    print(f"\n{'='*60}")
    print("Running Uptane Benchmark")
    print(f"Iterations: {iterations}")
    print(f"Signing/Verifying: {sign_label}")
    print(f"Payload enc/dec: {enc_label}")
    print(f"Hashing: {hash_label}")
    print(f"{'='*60}")

    # --- Setup Phase (Not timed for the flow benchmark) ---
    setup_start = time.perf_counter()
    director_priv, director_pub = key_gen_func()
    image_priv, image_pub = key_gen_func()
    sym_key = sym_key_gen()
    if debug: print(f"[Setup] Key generation took: {(time.perf_counter() - setup_start)*1000:.4f} ms")

    timings = {'sign': 0.0, 'verify': 0.0, 'hash': 0.0, 'decrypt': 0.0, 'encrypt': 0.0}

    def timed_sign(*args):
        start = time.perf_counter()
        res = sign_func(*args)
        timings['sign'] += (time.perf_counter() - start) * 1000
        return res

    def timed_verify(*args):
        start = time.perf_counter()
        res = verify_func(*args)
        timings['verify'] += (time.perf_counter() - start) * 1000
        return res

    def timed_hash(*args):
        start = time.perf_counter()
        res = hash_func(*args)
        timings['hash'] += (time.perf_counter() - start) * 1000
        return res

    def timed_decrypt(*args):
        start = time.perf_counter()
        res = decrypt_func(*args)
        timings['decrypt'] += (time.perf_counter() - start) * 1000
        return res

    def timed_encrypt(*args):
        start = time.perf_counter()
        res = encrypt_func(*args)
        timings['encrypt'] += (time.perf_counter() - start) * 1000
        return res

    director = DirectorRepository(director_priv, timed_sign, sym_key, debug=debug)
    image_repo = ImageRepository(image_priv, timed_sign, timed_hash, sym_key, timed_encrypt)
    ecu = VehicleECU("ECU_FRONT_01", timed_verify, timed_hash, timed_decrypt, director_pub, image_pub, debug=debug)

    total_flow_time = 0.0

    # ================= Benchmark the whole update flow =================
    for i in range(iterations):
        flow_start = time.perf_counter()
        
        if debug: print(f"\n[Iteration {i+1}] [{ecu.ecu_id}] Starting update pipeline. Current version: {ecu.installed_version}")
        
        # Step 1: Send Vehicle Manifest (currently installed versions + ECU identifiers)
        manifest = ecu.send_manifest()
        
        # Step 2: Analyse manifest, decide which firmware images to install
        # behövs väl inte
    
        # Step 3: Publish signed Targets metadata (specifying which update to install)
        director_payload = director.analyze_manifest_and_get_targets(manifest)
        if not director_payload:
            if debug: print(f"[{ecu.ecu_id}] No update needed according to Director.")
            return
    
        if debug: print(f"[{ecu.ecu_id}] Received target metadata from Director.")
        target_version = director_payload["metadata"]["target_version"]
        
        
        # Step 4a: Download Timestamp & Snapshot metadata 
        # behövs väl inte
    
        # Step 4b: Download Targets metadata
        image_repo_payload = image_repo.get_targets_metadata(target_version)
        if debug: print(f"[{ecu.ecu_id}] Received target metadata from Image Repository.")
    
        # Cross-validate metadata from Director & Image Repository. Verify all signatures.
        # If metadata invalid or signatures mismatch, abort update and log error.
        if not ecu.verify_metadata(director_payload, image_repo_payload):
            return
            
        # Step 5: Download firmware image
        if debug: print(f"[{ecu.ecu_id}] Metadata verified and signed. Downloading firmware {target_version}...")
        firmware = image_repo.download_firmware(target_version)
    
        # Verify SHA-256 hash and file size against metadata.
        if not ecu.verify_and_install_firmware(firmware, director_payload, image_repo_payload, target_version):
            return
    
        # Step 6: Send updated Vehicle Manifest (confirm successful installation)
        updated_manifest = ecu.send_manifest()
        director.confirm_update(updated_manifest)
        
        # Time calc
        total_flow_time += (time.perf_counter() - flow_start) * 1000
        
        # Reset ECU for next iteration
        ecu.installed_version = "v1.0"
    # Determine the payload size dynamically from the ECU's download context
    # raw_firmware inside image_repo is ~38000 bytes. 
    # For a more exact label, we fetch its size:
    payload_size_kb = len(image_repo.raw_firmware) / 1024.0

    print(f"--- Flow Complete (Average over {iterations} runs) ---")
    print(f"Avg Total UpdateTime: {total_flow_time / iterations:.4f} ms")
    print(f"Avg Signing Time:    {timings['sign'] / iterations:.4f} ms")
    print(f"Avg Verifying Time:  {timings['verify'] / iterations:.4f} ms")
    print(f"Avg Encrypting Time: {timings['encrypt'] / iterations:.4f} ms ({payload_size_kb:.1f}KB)")
    print(f"Avg Decrypting Time: {timings['decrypt'] / iterations:.4f} ms ({payload_size_kb:.1f}KB)")
    print(f"Avg Hashing Time:    {timings['hash'] / iterations:.4f} ms ({payload_size_kb:.1f}KB)")

def main():
    # Pass debug=True to see the pipeline traces, debug=False to only see benchmark results
    run_benchmark(
        "Ed25519", "SHA256", "AES-GCM",
        crypto.ed25519_keygen, 
        crypto.ed25519_sign, 
        crypto.ed25519_verify, 
        crypto.compute_sha256,
        crypto.aes_gcm_keygen,
        crypto.aes_gcm_encrypt,
        crypto.aes_gcm_decrypt,
        iterations=100,
        debug=False
    )

    run_benchmark(
        "RSA-2048", "SHA256", "ChaCha20-Poly1305",
        crypto.rsa_keygen, 
        crypto.rsa_sign, 
        crypto.rsa_verify, 
        crypto.compute_sha256,
        crypto.chacha20_keygen,
        crypto.chacha20_encrypt,
        crypto.chacha20_decrypt,
        iterations=100,
        debug=False
    )


if __name__ == "__main__":
    main()
