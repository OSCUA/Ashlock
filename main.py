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

# Setup vault
def setup_vault():
    os.makedirs(VAULT_DIR, exist_ok=True)
    password = getpass.getpass("Set vault password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # Save key securely (demo only — use secure storage in production)
    with open(KEY_FILE, "wb") as f:
        f.write(salt + key)

    # Optional time-lock setup
    if input("Enable time-locked self-destruct? (y/n): ").lower() == "y":
        expiry = input("Enter expiry datetime (YYYY-MM-DD HH:MM:SS UTC): ")
        mode = input("Deletion mode ('delete' or 'shred'): ").strip()
        meta = {"expiry": expiry, "mode": mode}
        with open(META_FILE, "w") as f:
            json.dump(meta, f)
        print("[+] Time-lock enabled.")

    print("[+] Vault setup complete.")

# Mount vault
def mount_vault():
    if not os.path.exists(KEY_FILE):
        print("[!] Vault key missing.")
        return

    with open(KEY_FILE, "rb") as f:
        data = f.read()
        salt, key = data[:16], data[16:]

    if os.path.exists(META_FILE):
        with open(META_FILE, "r") as f:
            meta = json.load(f)
        check_expiration(meta)

    print("[+] Vault mounted. You may access files in:", VAULT_DIR)

# Ritual menu
def main():
    print("=== Shrine Vault ===")
    choice = input("Choose: [1] Setup Vault  [2] Mount Vault\n> ")
    if choice == "1":
        setup_vault()
    elif choice == "2":
        mount_vault()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
