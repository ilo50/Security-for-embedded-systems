import time
from director_repo import DirectorRepository
from image_repo import ImageRepository
from vehicle_ecu import VehicleECU
import crypto_algorithms as crypto

def run_benchmark(dir_sign_label, image_sign_label, hash_label, enc_label, 
                  dir_key_gen_func, dir_sign_func, dir_verify_func, 
                  image_key_gen_func, image_sign_func, image_verify_func, 
                  hash_func, sym_key_gen, encrypt_func, decrypt_func, iterations=100, debug=False):
    """Orchestrates the modular components, showing the Uptane pipeline and timing it."""
    print(f"\n{'='*60}")
    print("Running Uptane Benchmark")
    print(f"Iterations: {iterations}")
    print(f"Director Sign/Verify: {dir_sign_label}")
    print(f"Image Repo Sign/Verify: {image_sign_label}")
    print(f"Payload enc/dec: {enc_label}")
    print(f"Hashing: {hash_label}")
    print(f"{'='*60}")

    # --- Setup Phase (Not timed for the flow benchmark) ---
    setup_start = time.perf_counter()
    director_priv, director_pub = dir_key_gen_func()
    image_priv, image_pub = image_key_gen_func()
    ecu_priv, ecu_pub = dir_key_gen_func()
    sym_key = sym_key_gen()
    if debug: print(f"[Setup] Key generation took: {(time.perf_counter() - setup_start)*1000:.4f} ms")

    timer = crypto.BenchmarkTimer(iterations)

    director = DirectorRepository(
        director_priv, 
        timer.timed_op(dir_sign_func, 'identity_sign'), 
        sym_key, 
        ecu_pub, 
        timer.timed_op(dir_verify_func, 'identity_verify'), 
        debug=debug
    )
    image_repo = ImageRepository(
        image_priv, 
        timer.timed_op(image_sign_func, 'payload_sign'), 
        timer.timed_op(hash_func, 'hash'), 
        sym_key, 
        timer.timed_op(encrypt_func, 'encrypt')
    )
    ecu = VehicleECU(
        "ECU_FRONT_01", 
        ecu_priv, 
        timer.timed_op(dir_sign_func, 'identity_sign'), 
        timer.timed_op(dir_verify_func, 'identity_verify'), 
        timer.timed_op(image_verify_func, 'payload_verify'), 
        timer.timed_op(hash_func, 'hash'), 
        timer.timed_op(decrypt_func, 'decrypt'), 
        director_pub, 
        image_pub, 
        debug=debug
    )

    # ================= Benchmark the whole update flow =================
    for i in range(iterations):
        flow_start = time.perf_counter()
        
        if debug: print(f"\n[Iteration {i+1}] [{ecu.ecu_id}] Starting update pipeline. Current version: {ecu.installed_version}")
        
        # Step 1: Send Vehicle Manifest (currently installed versions + ECU identifiers)
        # this step can be done using symmetric key. (test this)
        manifest = ecu.send_manifest()
        
        # Step 2: Analyse manifest, decide which firmware images to install
        # behövs väl inte
        #  - jo tror att det är bra för att directorns måste verify signaturen av ECU 
        # ( kan göras med antingen symmetric eller asymmetric keys) vilket vi får testa

        # FIX
        # Lade till sign/verif i ecu.send_manifest och director_repo.py och använder just nu asymmetrisk kryptering
    
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
        timer.add_flow_time((time.perf_counter() - flow_start) * 1000)
        
        # Reset ECU for next iteration
        ecu.installed_version = "v1.0"
    # Determine the payload size dynamically from the ECU's download context
    # raw_firmware inside image_repo is ~38000 bytes. 
    # For a more exact label, we fetch its size:
    payload_size_kb = len(image_repo.raw_firmware) / 1024.0

    timer.print_results(payload_size_kb)

def main():
    # 1: Sign/verf: Vehicle <-> Director
    # 2: Sign/verf: Image Repo -> Vehicle
    # 3: Hash: Firmware Payload
    # 4: Encrypt/Decrypt: Firmware Payload
    
    # --- 1: Asymmetric / Asymmetric ---
    run_benchmark(
        "Ed25519", "Ed25519", "SHA256", "AES-GCM",
        crypto.ed25519_keygen, crypto.ed25519_sign, crypto.ed25519_verify, 
        crypto.ed25519_keygen, crypto.ed25519_sign, crypto.ed25519_verify, 
        crypto.compute_sha256,
        crypto.aes_gcm_keygen,
        crypto.aes_gcm_encrypt,
        crypto.aes_gcm_decrypt,
        iterations=100,
        debug=False
    )

    # --- 1 (Alternative): Asymmetric / Asymmetric (RSA) ---
    run_benchmark(
        "RSA-2048", "RSA-2048", "SHA256", "ChaCha20-Poly1305",
        crypto.rsa_keygen, crypto.rsa_sign, crypto.rsa_verify, 
        crypto.rsa_keygen, crypto.rsa_sign, crypto.rsa_verify, 
        crypto.compute_sha256,
        crypto.chacha20_keygen,
        crypto.chacha20_encrypt,
        crypto.chacha20_decrypt,
        iterations=100,
        debug=False
    )

    # --- 3: Symmetric (HMAC) / Asymmetric (Ed25519) ---
    run_benchmark(
        "HMAC-SHA256", "Ed25519", "SHA256", "AES-GCM",
        crypto.hmac_keygen, crypto.hmac_sign, crypto.hmac_verify, 
        crypto.ed25519_keygen, crypto.ed25519_sign, crypto.ed25519_verify, 
        crypto.compute_sha256,
        crypto.aes_gcm_keygen,
        crypto.aes_gcm_encrypt,
        crypto.aes_gcm_decrypt,
        iterations=100,
        debug=False
    )

    # --- 4: Symmetric (HMAC) / Symmetric (HMAC) ---
    run_benchmark(
        "HMAC-SHA256", "HMAC-SHA256", "SHA256", "AES-GCM",
        crypto.hmac_keygen, crypto.hmac_sign, crypto.hmac_verify, 
        crypto.hmac_keygen, crypto.hmac_sign, crypto.hmac_verify, 
        crypto.compute_sha256,
        crypto.aes_gcm_keygen,
        crypto.aes_gcm_encrypt,
        crypto.aes_gcm_decrypt,
        iterations=100,
        debug=False
    )


if __name__ == "__main__":
    main()
