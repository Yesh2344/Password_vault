# Secure Password Vault

## Overview

This is a secure, local password management application that allows users to store and retrieve encrypted passwords using a master password. The application uses Fernet symmetric encryption to protect sensitive information and provides a simple command-line interface for managing passwords.

## Features

- 🔐 Master password protection
- 🔒 Encryption of stored passwords
- 💾 Local file-based storage
- 🖥️ Simple command-line interface
- 🔑 Automatic key generation

## Prerequisites

- Python 3.7+
- Required libraries:
  - `cryptography`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-vault.git
   cd password-vault
   ```

2. Install required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

### First-Time Setup
- When you first run the script, you'll be prompted to set a master password.
- This master password will be used to access your password vault in future sessions.

### Running the Application
```bash
python password_vault.py
```

### Options
1. **Add Password**
   - Enter the service name
   - Enter the username
   - Enter the password (hidden input)

2. **Retrieve Password**
   - Enter the service name
   - View username and password if found

3. **Exit**
   - Safely close the application

## Security Notes

- Passwords are encrypted using Fernet symmetric encryption
- A unique encryption key is generated and stored locally
- Master password is hashed using SHA-256
- Passwords are stored in a local JSON file

## Files Created

- `key.key`: Encryption key for password vault
- `vault.json`: Encrypted password storage
- `master_hash.txt`: Hashed master password

## Potential Improvements

- Add password generation feature
- Implement password strength checker
- Create a GUI interface
- Add export/import functionality

## Security Warnings

- Keep `key.key`, `vault.json`, and `master_hash.txt` secure
- Do not share these files
- Use a strong, unique master password

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Choose an appropriate license, e.g., MIT License]

## Disclaimer

This is a basic password management solution. For critical security needs, consider professional password managers.
