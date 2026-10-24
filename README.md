# CryptoShield — Next-Gen Cryptography & Network Security (CNS) Innovation Suite

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![Cryptography](https://img.shields.io/badge/PyCryptodome-3.20.0-orange.svg)](https://pycryptodome.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**CryptoShield** is an advanced, full-featured web-based Cryptography and Network Security (CNS) educational and demonstration platform. It goes far beyond basic text encryption by implementing industry-standard hybrid protocols, visual steganography, pixel-level cipher mode leakage demonstrations, multi-cipher playgrounds, encrypted QR vaults, and X.509 PKI certificate chain simulators.

---

## 🌟 Key Innovative Features

### 1. 🛡️ Adaptive Hybrid Cryptography & File Vault
- **AES-256-CBC + RSA-2048**: Symmetric high-speed data encryption combined with asymmetric RSA-OAEP session key encapsulation.
- **SHA-256 Integrity Digests**: Cryptographic hashing to prevent silent data corruption.
- **RSA Digital Signatures**: Non-repudiation and authentication using RSA-PSS / PKCS#1 v1.5 with sender private keys.
- **Interactive Tamper Simulator**: Intercept ciphertext or auth tags in transit to demonstrate how MAC and signature verifications catch malicious tampering in real-time.

### 2. 🖼️ Visual Image Encryption & ECB vs CBC Leak Analysis
- **Direct Visual Image Encryption**: Encrypt images (PNG, JPEG, BMP) and visually preview the encrypted image.
- **ECB vs CBC Mode Demonstration**: The classic "ECB Penguin" phenomenon demonstrated live! Shows how ECB preserves pixel patterns and silhouette outlines, whereas CBC produces pseudo-random cryptographic diffusion.
- **Shannon Entropy & Histogram**: Computes and charts entropy and pixel intensity distribution before and after encryption.

### 3. 🕵️ LSB Image Steganography Lab
- **Carrier Image Hiding**: Embed confidential messages and files directly inside the Least Significant Bits (LSB) of PNG/BMP pixels without noticeable visual degradation.
- **Extraction & Bit-Plane Inspection**: Extract hidden messages and visualize individual bit planes to inspect where information is concealed.

### 4. 🕹️ Multi-Cipher Playground & Comparative Analytics
- **Classical vs Modern Ciphers**: Test and compare Caesar Cipher, Vigenère Cipher, Playfair Cipher, Hill Cipher, DES, and AES (128/192/256-bit).
- **Metric Comparison**: Real-time analysis of avalanche effect, key space, speed, and resistance to cryptanalysis.

### 5. 📱 Encrypted QR Code Vault
- **Password-Derived Keys**: Uses PBKDF2 (100,000 iterations) with cryptographic salt to derive 256-bit keys.
- **AES-GCM Authenticated Encryption**: Protects secret notes, credentials, and seeds inside scannable QR codes.
- **Live In-Browser & Server Decryption**: Scan or upload QR codes to authenticate and unlock encrypted payloads.

### 6. 📜 PKI & X.509 Certificate Chain Simulator
- **Chain of Trust**: Interactively generate a Root Certificate Authority (Root CA), issue Intermediate CAs, and sign End-Entity (SSL/TLS) digital certificates.
- **Certificate Inspection & Verification**: Inspect Subject, Issuer, Validity Dates, Extensions, and verify cryptographic signature validity along the trust chain.

---

## 🏗️ Cryptographic Architecture

```
Sender Side:
  [Plaintext / File] ──► SHA-256 ──► Sign with Sender Private Key ──► [Digital Signature]
         │
         ▼
  AES-256-CBC Encryption (Random 256-bit Key & 16-byte IV) ─────────► [Ciphertext Payload]
         │
         ▼
  AES Session Key ──► RSA-OAEP Encrypt with Receiver Public Key ────► [Encrypted Session Key]
         │
         ▼
  Bundled Package: { Ciphertext, Encrypted Key, IV, Signature, Metadata }

Receiver Side:
  [Encrypted Session Key] ──► Decrypt with Receiver Private Key ──► [AES Session Key]
         │
         ▼
  [Ciphertext Payload] ──► AES-256-CBC Decrypt with IV ──────────► [Plaintext File]
         │
         ▼
  Re-calculate SHA-256 & Verify Sender Digital Signature ─────────► [Integrity & Authenticity VERIFIED]
```

---

## 🚀 Installation & Quickstart

### Prerequisites
- Python 3.9+
- Git

### 1. Clone the repository:
```bash
git clone https://github.com/Akashk132/CNS.git
cd CNS
```

### 2. Set up virtual environment:
```bash
python -m venv venv

# Windows:
.\venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate
```

### 3. Install dependencies:
```bash
pip install -r requirements.txt
```

### 4. Start the application:
```bash
python app.py
```

### 5. Access the web interface:
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📁 Repository Structure

```
CNS/
├── app.py              # Main Flask server, cryptographic routes & algorithms
├── requirements.txt    # Python dependencies (pycryptodome, pillow, qrcode, pyOpenSSL)
├── static/
│   ├── style.css       # Responsive dark-mode styling with glassmorphism
│   └── ...             # Frontend assets
├── templates/
│   └── index.html      # Modular single-page app with tabs for all 6 CNS labs
├── keys/               # Generated RSA PEM keys
└── uploads/            # Temporary secure upload directory
```

---

## 🔒 Security Notice
This project is built for educational, academic, and research purposes in Cryptography and Network Security courses. While AES-256, RSA-2048, and SHA-256 implement cryptographic standards via `pycryptodome` and `pyOpenSSL`, production deployments should also incorporate secure hardware modules (HSMs) and hardened TLS termination.

---

## 📄 License
This project is open-source and licensed under the [MIT License](LICENSE).
