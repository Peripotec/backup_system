"""
Credential Vault - Encrypted storage for credentials.
Uses Fernet symmetric encryption.
"""
import os
import yaml
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vault.yaml')
VAULT_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.vault_key')

def _get_or_create_key():
    """Get or create encryption key."""
    if os.path.exists(VAULT_KEY_FILE):
        with open(VAULT_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = Fernet.generate_key()
        with open(VAULT_KEY_FILE, 'wb') as f:
            f.write(key)
        # Set restrictive permissions
        try:
            os.chmod(VAULT_KEY_FILE, 0o600)
        except:
            pass
        return key

def _get_fernet():
    """Get Fernet instance."""
    return Fernet(_get_or_create_key())

def encrypt(plaintext):
    """Encrypt a string."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()

def decrypt(ciphertext):
    """Decrypt a string."""
    if not ciphertext:
        return ""
    try:
        f = _get_fernet()
        return f.decrypt(ciphertext.encode()).decode()
    except:
        return ""  # Return empty on decrypt failure

def load_vault():
    """Load vault from file."""
    if not os.path.exists(VAULT_FILE):
        return {"credentials": []}
    try:
        with open(VAULT_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {"credentials": []}
    except:
        return {"credentials": []}

def save_vault(data):
    """Save vault to file."""
    with open(VAULT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def get_credentials_list():
    """Get list of credentials (without passwords)."""
    vault = load_vault()
    result = []
    for cred in vault.get("credentials", []):
        result.append({
            "id": cred["id"],
            "name": cred["name"],
            "user": cred.get("user", "")
        })
    return result

def get_credential_by_id(cred_id):
    """Get a single credential with decrypted password."""
    vault = load_vault()
    for cred in vault.get("credentials", []):
        if cred["id"] == cred_id:
            return {
                "id": cred["id"],
                "name": cred["name"],
                "user": cred.get("user", ""),
                "pass": decrypt(cred.get("pass_encrypted", "")),
                "extra_pass": decrypt(cred.get("extra_pass_encrypted", ""))
            }
    return None

def add_credential(cred_id, name, user, password, extra_pass=""):
    """Add a new credential."""
    vault = load_vault()
    
    # Check for duplicate ID
    for c in vault.get("credentials", []):
        if c["id"] == cred_id:
            return False, "ID ya existe"
    
    vault["credentials"].append({
        "id": cred_id,
        "name": name,
        "user": user,
        "pass_encrypted": encrypt(password),
        "extra_pass_encrypted": encrypt(extra_pass) if extra_pass else ""
    })
    save_vault(vault)
    return True, "Credencial agregada"

def update_credential(cred_id, name=None, user=None, password=None, extra_pass=None):
    """Update an existing credential."""
    vault = load_vault()
    for cred in vault.get("credentials", []):
        if cred["id"] == cred_id:
            if name is not None:
                cred["name"] = name
            if user is not None:
                cred["user"] = user
            if password is not None and password != "":
                cred["pass_encrypted"] = encrypt(password)
            if extra_pass is not None:
                cred["extra_pass_encrypted"] = encrypt(extra_pass) if extra_pass else ""
            save_vault(vault)
            return True, "Credencial actualizada"
    return False, "Credencial no encontrada"

def delete_credential(cred_id):
    """Delete a credential."""
    vault = load_vault()
    original_len = len(vault.get("credentials", []))
    vault["credentials"] = [c for c in vault.get("credentials", []) if c["id"] != cred_id]
    if len(vault["credentials"]) < original_len:
        save_vault(vault)
        return True, "Credencial eliminada"
    return False, "Credencial no encontrada"

def get_credentials_for_group(credential_ids):
    """Get decrypted credentials for a list of IDs (for backup execution)."""
    result = []
    for cred_id in credential_ids:
        cred = get_credential_by_id(cred_id)
        if cred:
            result.append(cred)
    return result

# Credential cache - stores which credential worked for which device
CREDENTIAL_CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.credential_cache.yaml')

def _load_credential_cache():
    """Load credential cache from file."""
    if not os.path.exists(CREDENTIAL_CACHE_FILE):
        return {}
    try:
        with open(CREDENTIAL_CACHE_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except:
        return {}

def _save_credential_cache(cache):
    """Save credential cache to file."""
    with open(CREDENTIAL_CACHE_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(cache, f, default_flow_style=False, allow_unicode=True)

def get_preferred_credential_for_device(hostname):
    """Get the preferred credential ID for a device (from cache)."""
    cache = _load_credential_cache()
    return cache.get(hostname)

def save_preferred_credential_for_device(hostname, cred_id):
    """Save which credential worked for a device."""
    cache = _load_credential_cache()
    cache[hostname] = cred_id
    _save_credential_cache(cache)

def get_credentials_for_device(hostname, credential_ids):
    """
    Get credentials for a device, with preferred one first.
    Returns list of decrypted credentials, ordered by preference.
    """
    # Get preferred credential for this device
    preferred_id = get_preferred_credential_for_device(hostname)
    
    result = []
    
    # Add preferred credential first if it exists and is in the allowed list
    if preferred_id and preferred_id in credential_ids:
        cred = get_credential_by_id(preferred_id)
        if cred:
            result.append(cred)
    
    # Add remaining credentials
    for cred_id in credential_ids:
        if cred_id != preferred_id:  # Skip if already added as preferred
            cred = get_credential_by_id(cred_id)
            if cred:
                result.append(cred)
    
    return result
