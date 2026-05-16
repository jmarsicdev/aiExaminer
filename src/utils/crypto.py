import hashlib

def calculate_hashes(file_bytes):
    """Calculates MD5 and SHA256 hashes for the given bytes."""
    if file_bytes is None:
        return {"md5": None, "sha256": None}
    
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    return {
        "md5": md5_hash,
        "sha256": sha256_hash
    }
