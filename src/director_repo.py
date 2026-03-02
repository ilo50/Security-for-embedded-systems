class DirectorRepository:
    def __init__(self, private_key, sign_func, symmetric_key, ecu_public_key, verify_func, debug=False):
        self.private_key = private_key
        self.sign_func = sign_func
        self.symmetric_key = symmetric_key
        self.ecu_public_key = ecu_public_key
        self.verify_func = verify_func
        self.debug = debug

    def analyze_manifest_and_get_targets(self, payload):
        """Step 2 & 3: Analyze ECU state, decide next version, return signed metadata."""
        manifest = payload.get("manifest")
        signature = bytes.fromhex(payload.get("signature", ""))

        # Verify ECU signature before doing anything
        manifest_bytes = str(manifest).encode('utf-8')
        try:
            self.verify_func(self.ecu_public_key, signature, manifest_bytes)
            if self.debug: print(f"[Director] Successfully verified manifest signature from ECU.")
        except Exception:
            if self.debug: print(f"[Director] [FAIL] ECU Manifest signature verification failed! Rejecting request.")
            return None

        current_version = manifest.get("installed_version")
        target_version = "v2.0" # Hardcoded target for simulation
        
        if current_version == target_version:
            return None # No update needed
            
        metadata = {
            "ecu_id": manifest.get("ecu_id"),
            "target_version": target_version,
            "symmetric_key": self.symmetric_key.hex() # Secure delivery of decryption key
        }
        
        # Sign the metadata directing the ECU to download the specific version
        signature = self.sign_func(self.private_key, str(metadata).encode('utf-8'))
        return {"metadata": metadata, "signature": signature}

    def confirm_update(self, manifest):
        """Step 6: Confirm the final update installation state."""
        if self.debug: print(f"[Director] [OK] Update confirmed for {manifest['ecu_id']}: successfully running {manifest['installed_version']}")
