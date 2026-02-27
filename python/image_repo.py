class ImageRepository:
    def __init__(self, private_key, sign_func, hash_func):
        self.private_key = private_key
        self.sign_func = sign_func
        self.hash_func = hash_func
        # Simulate an actual firmware blob available in the repo
        self.firmwares = {
            "v2.0": b"1010101_FIRMWARE_PAYLOAD_DATA_1010101" * 1000  # Fake binary payload
        }

    def get_targets_metadata(self, version):
        """Step 3b/4b: Provide signed targets metadata specifying update details."""
        firmware = self.firmwares.get(version)
        if not firmware:
            return None
            
        file_size = len(firmware)
        file_hash = self.hash_func(firmware)
        
        # This metadata represents what the image repo declares to be truthful
        metadata = {
            "version": version,
            "size": file_size,
            "hash": file_hash.hex() # using hex for easy readability
        }
        
        # Sign the metadata
        signature = self.sign_func(self.private_key, str(metadata).encode('utf-8'))
        return {"metadata": metadata, "signature": signature}

    def download_firmware(self, version):
        """Step 5: Provide the raw firmware image."""
        return self.firmwares.get(version)
