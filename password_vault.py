import os
import json
import base64
from cryptography.fernet import Fernet
from hashlib import sha256
import getpass

# Generate or load the encryption key
def load_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    return key

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Hash the master password
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Load vault data
def load_vault(file="vault.json"):
    if not os.path.exists(file):
        return {}
    with open(file, "r") as f:
        return json.load(f)

# Save vault data
def save_vault(data, file="vault.json"):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# Add a password to the vault
def add_password(vault, key):
    service = input("Enter the service name: ").strip()
    username = input("Enter the username: ").strip()
    password = getpass.getpass("Enter the password: ").strip()
    
    encrypted_password = encrypt_data(password, key)
    vault[service] = {"username": username, "password": base64.b64encode(encrypted_password).decode()}
    save_vault(vault)
    print(f"Password for {service} saved successfully!")

# Retrieve a password
def retrieve_password(vault, key):
    service = input("Enter the service name to retrieve: ").strip()
    if service in vault:
        username = vault[service]["username"]
        encrypted_password = base64.b64decode(vault[service]["password"])
        password = decrypt_data(encrypted_password, key)
        print(f"Service: {service}\nUsername: {username}\nPassword: {password}")
    else:
        print("No record found for this service.")

# Main function
def main():
    key = load_key()
    master_password_hash = "master_hash.txt"
    
    # First-time setup
    if not os.path.exists(master_password_hash):
        master_password = getpass.getpass("Set a master password: ").strip()
        with open(master_password_hash, "w") as f:
            f.write(hash_password(master_password))
        print("Master password set successfully!")
    else:
        # Verify master password
        master_password = getpass.getpass("Enter the master password: ").strip()
        with open(master_password_hash, "r") as f:
            stored_hash = f.read()
        if stored_hash != hash_password(master_password):
            print("Invalid master password. Exiting...")
            return

    # Load or create vault
    vault = load_vault()
    while True:
        print("\nOptions:\n1. Add Password\n2. Retrieve Password\n3. Exit")
        choice = input("Choose an option: ").strip()
        
        if choice == "1":
            add_password(vault, key)
        elif choice == "2":
            retrieve_password(vault, key)
        elif choice == "3":
            print("Exiting... Stay secure!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
