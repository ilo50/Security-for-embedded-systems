class DirectorRepository:
    def __init__(self, private_key, sign_func, symmetric_key, debug=False):
        self.private_key = private_key
        self.sign_func = sign_func
        self.symmetric_key = symmetric_key
        self.debug = debug

    def analyze_manifest_and_get_targets(self, manifest):
        """Step 2 & 3: Analyze ECU state, decide next version, return signed metadata."""
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
