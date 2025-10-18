import os
import json
import shutil
import getpass
import requests
from datetime import datetime
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VAULT_DIR = "vault_data"
META_FILE = "vault_meta.json"
KEY_FILE = "vault.key"

# Derive encryption key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

# Get current UTC time from trusted API
def get_utc_time():
    try:
        response = requests.get("https://worldtimeapi.org/api/timezone/Etc/UTC", timeout=5)
        response.raise_for_status()
        utc_str = response.json()["utc_datetime"]
        return datetime.fromisoformat(utc_str.replace("Z", "+00:00"))
    except Exception as e:
        print(f"[ERROR] Failed to fetch UTC time: {e}")
        return None

# Check if vault should self-destruct
def check_expiration(meta):
    expiry = datetime.fromisoformat(meta["expiry"])
    now = get_utc_time()
    if now and now >= expiry:
        print("[!] Vault expired. Initiating self-destruct...")
        if meta["mode"] == "delete":
            shutil.rmtree(VAULT_DIR, ignore_errors=True)
        elif meta["mode"] == "shred":
            os.remove(KEY_FILE)
        exit()

# Encrypt all files in the vault
def encrypt_vault(key: bytes):
    for root, _, files in os.walk(VAULT_DIR):
        for file in files:
            path = os.path.join(root, file)
            if path.endswith(".enc"):
                continue
            with open(path, "rb") as f:
                data = f.read()
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(nonce, data, None)
            with open(path + ".enc", "wb") as f:
                f.write(nonce + encrypted)
            os.remove(path)
    print("[🔒] Vault locked and encrypted.")

# Decrypt all .enc files in the vault
def decrypt_vault(key: bytes):
    for root, _, files in os.walk(VAULT_DIR):
        for file in files:
            if not file.endswith(".enc"):
                continue
            path = os.path.join(root, file)
            with open(path, "rb") as f:
                nonce = f.read(12)
                encrypted = f.read()
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, encrypted, None)
            with open(path.replace(".enc", ""), "wb") as f:
                f.write(decrypted)
            os.remove(path)
    print("[🔓] Vault unlocked and decrypted.")

# Setup vault
def setup_vault():
    os.makedirs(VAULT_DIR, exist_ok=True)
    password = getpass.getpass("Set vault password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(KEY_FILE, "wb") as f:
        f.write(salt + key)

    if input("Enable time-locked self-destruct? (y/n): ").lower() == "y":
        expiry = input("Enter expiry datetime (YYYY-MM-DD HH:MM:SS UTC): ")
        mode = input("Deletion mode ('delete' or 'shred'): ").strip()
        meta = {"expiry": expiry, "mode": mode}
        with open(META_FILE, "w") as f:
            json.dump(meta, f)
        print("[+] Time-lock enabled.")

    print("[+] Vault setup complete.")

# Load key from file
def load_key():
    if not os.path.exists(KEY_FILE):
        print("[!] Vault key missing.")
        return None, None
    with open(KEY_FILE, "rb") as f:
        data = f.read()
        return data[:16], data[16:]

# Mount vault
def mount_vault():
    salt, key = load_key()
    if not key:
        return
    if os.path.exists(META_FILE):
        with open(META_FILE, "r") as f:
            meta = json.load(f)
        check_expiration(meta)
    print("[+] Vault mounted. You may access files in:", VAULT_DIR)

# Lock vault
def lock_vault():
    salt, key = load_key()
    if not key:
        return
    encrypt_vault(key)

# Unlock vault
def unlock_vault():
    salt, key = load_key()
    if not key:
        return
    decrypt_vault(key)

# Ritual menu
def main():
    print("=== Shrine Vault: Ashlock ===")
    print("[1] Setup Vault")
    print("[2] Mount Vault")
    print("[3] Lock Vault")
    print("[4] Unlock Vault")
    choice = input("> ")
    if choice == "1":
        setup_vault()
    elif choice == "2":
        mount_vault()
    elif choice == "3":
        lock_vault()
    elif choice == "4":
        unlock_vault()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
