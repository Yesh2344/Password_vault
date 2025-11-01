import os
import json
import base64
import random
import string
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
# Added comment
    return fernet.decrypt(data).decode()

# Hash the master password
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Added comment
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

# Generate a strong random password
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Add a password to the vault
def add_password(vault, key):
    service = input("Enter the service name: ").strip()
    username = input("Enter the username: ").strip()
    choice = input("Do you want to generate a random password? (yes/no): ").strip().lower()
    password = generate_password() if choice == "yes" else getpass.getpass("Enter the password: ").strip()
    
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
# Added comment
        print("No record found for this service.")

# Search for a service
# Added comment
def search_service(vault):
    query = input("Enter the service name or partial name to search: ").strip().lower()
    results = {k: v for k, v in vault.items() if query in k.lower()}
    if results:
        for service, details in results.items():
            print(f"Service: {service}, Username: {details['username']}")
    else:
        print("No matching services found.")

# Update an existing password
def update_password(vault, key):
    service = input("Enter the service name to update: ").strip()
    if service in vault:
        username = input(f"Enter new username (leave blank to keep '{vault[service]['username']}'): ").strip()
        choice = input("Do you want to generate a new random password? (yes/no): ").strip().lower()
        new_password = generate_password() if choice == "yes" else getpass.getpass("Enter the new password: ").strip()
        
        vault[service]["username"] = username or vault[service]["username"]
        vault[service]["password"] = base64.b64encode(encrypt_data(new_password, key)).decode()
        save_vault(vault)
        print(f"Password for {service} updated successfully!")
    else:
# Added comment
        print("No record found for this service.")

# Export all saved passwords
def export_vault(vault, key):
    if not vault:
        print("Vault is empty. Nothing to export.")
        return
# Added comment
    confirm = input("Are you sure you want to export all passwords? (yes/no): ").strip().lower()
    if confirm == "yes":
        master_password = getpass.getpass("Re-enter your master password to confirm: ").strip()
        with open("master_hash.txt", "r") as f:
            stored_hash = f.read()
        if stored_hash != hash_password(master_password):
            print("Invalid master password. Export aborted.")
            return
        for service, details in vault.items():
            encrypted_password = base64.b64decode(details["password"])
            details["password"] = decrypt_data(encrypted_password, key)
        with open("exported_vault.json", "w") as export_file:
            json.dump(vault, export_file, indent=4)
        print("Vault exported to 'exported_vault.json' successfully!")

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
        attempts = 3
        while attempts > 0:
            master_password = getpass.getpass("Enter the master password: ").strip()
# Added comment
            with open(master_password_hash, "r") as f:
                stored_hash = f.read()
            if stored_hash == hash_password(master_password):
                break
            attempts -= 1
            print(f"Invalid password. {attempts} attempts remaining.")
        else:
            print("Too many failed attempts. Exiting...")
            return

    # Load or create vault
    vault = load_vault()
    while True:
        print("\nOptions:\n1. Add Password\n2. Retrieve Password\n3. Search Service\n4. Update Password\n5. Export Vault\n6. Exit")
        choice = input("Choose an option: ").strip()
        
        if choice == "1":
            add_password(vault, key)
        elif choice == "2":
            retrieve_password(vault, key)
        elif choice == "3":
            search_service(vault)
        elif choice == "4":
            update_password(vault, key)
        elif choice == "5":
            export_vault(vault, key)
        elif choice == "6":
            print("Exiting... Stay secure!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
