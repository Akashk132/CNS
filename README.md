# CryptoShield — Adaptive Hybrid Cryptography for Secure File Transmission

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

CryptoShield is a web-based cryptographic security system designed to demonstrate and implement secure end-to-end file transmission using hybrid cryptography techniques.

## Features

- **Hybrid Cryptography**: Combines the high efficiency of symmetric encryption (**AES-256-CBC**) with the secure key-exchange guarantees of asymmetric encryption (**RSA-2048 / RSA-OAEP**).
- **Integrity Verification**: Generates **SHA-256** digests of payload data to ensure tamper resistance.
- **Authentication & Non-Repudiation**: Digital signatures generated using **RSA-PSS / PKCS#1 v1.5** with sender's private key.
- **Key Pair Management**: Web interface for generating and downloading 2048-bit RSA public and private keys.
- **Interactive Security Playground**:
  - Encrypt and transmit bundles with ciphertext, encrypted symmetric key, initialization vector (IV), and digital signature.
  - Decrypt bundles with automatic signature and hash verification.
  - **Tamper Simulation**: Intentionally alter ciphertext or metadata in transit to observe cryptographic integrity alerts and detection mechanisms.

## Cryptographic Architecture

1. **Key Generation**: Sender and receiver generate RSA-2048 keypairs.
2. **Encryption Process**:
   - Computes SHA-256 hash of original file.
   - Signs file hash with sender's RSA private key.
   - Generates random 256-bit AES session key and 16-byte IV.
   - Encrypts file payload using AES-256-CBC with PKCS#7 padding.
   - Encrypts AES session key using receiver's RSA public key (RSA-OAEP).
   - Bundles encrypted payload, wrapped AES key, IV, signature, and metadata.
3. **Decryption Process**:
   - Decrypts AES session key using receiver's RSA private key.
   - Decrypts file payload using recovered AES key and IV.
   - Verifies sender's digital signature against recovered plaintext.
   - Re-computes SHA-256 hash and validates file integrity.

## Prerequisites

- Python 3.9+
- `pip` package manager

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Akashk132/CNS.git
   cd CNS
   ```

2. **Create and activate a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Flask application:**
   ```bash
   python app.py
   ```

5. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

## Project Structure

```
CNS/
├── app.py              # Flask server and cryptography endpoints
├── requirements.txt    # Project dependencies
├── static/             # Frontend assets (CSS, logo)
├── templates/          # Frontend HTML templates
├── keys/               # Generated RSA PEM keys
└── uploads/            # Temporary file storage
```
