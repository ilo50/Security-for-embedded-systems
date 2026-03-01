class VehicleECU:
    def __init__(self, ecu_id, verify_func, hash_func, decrypt_func, director_public_key, image_repo_public_key, debug=False):
        self.ecu_id = ecu_id
        self.installed_version = "v1.0"
        self.verify_func = verify_func
        self.hash_func = hash_func
        self.decrypt_func = decrypt_func
        self.director_public_key = director_public_key
        self.image_repo_public_key = image_repo_public_key
        self.debug = debug

    def send_manifest(self):
        """Step 1 & Step 6: Generate Vehicle Manifest"""
        return {"ecu_id": self.ecu_id, "installed_version": self.installed_version}

    def verify_metadata(self, director_payload, image_repo_payload):
        if self.debug: print(f"[{self.ecu_id}] Cross-validating metadata and verifying signatures...")
        try:
            self.verify_func(self.director_public_key, director_payload["signature"], str(director_payload["metadata"]).encode('utf-8'))
            self.verify_func(self.image_repo_public_key, image_repo_payload["signature"], str(image_repo_payload["metadata"]).encode('utf-8'))
        except Exception as e:
            if self.debug: print(f"[{self.ecu_id}] [FAIL] Signature Validation Failed. Aborting update error: {e}")
            return False

        # Explicit Verification logic: Ensure Director and Image Repo are pointing to the same version
        if director_payload["metadata"]["target_version"] != image_repo_payload["metadata"]["version"]:
            if self.debug: print(f"[{self.ecu_id}] [FAIL] Metadata Target Version mismatch! Aborting update.")
            return False
            
        return True

    def verify_and_install_firmware(self, firmware, director_payload, image_repo_payload, target_version):
        # 1. Verify against metadata of the downloaded (raw encrypted) firmware first
        expected_size = image_repo_payload["metadata"]["size"]
        expected_hash = image_repo_payload["metadata"]["hash"]

        actual_size = len(firmware)
        actual_hash = self.hash_func(firmware).hex()

        if actual_size != expected_size or actual_hash != expected_hash:
            if self.debug: print(f"[{self.ecu_id}] [FAIL] Firmware payload hash/size mismatch. Aborting update.")
            return False

        # 2. Step 4.5: Decrypt Firmware using the symmetric key securely delivered in Step 3
        if self.debug: print(f"[{self.ecu_id}] Hash verified! Decrypting downloaded firmware...")
        symmetric_key = bytes.fromhex(director_payload["metadata"]["symmetric_key"])
        
        try:
            decrypted_firmware = self.decrypt_func(symmetric_key, firmware)
        except Exception as e:
            if self.debug: print(f"[{self.ecu_id}] [FAIL] Firmware decryption failed! Aborting update error: {e}")
            return False

        if self.debug: print(f"[{self.ecu_id}] [OK] Firmware verification and decryption succeeds. Installing firmware...")
        self.installed_version = target_version
        return True
