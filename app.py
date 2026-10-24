"""
CryptoShield — Adaptive Hybrid Cryptography for Secure File Transmission
=========================================================================
Backend server providing:
  • RSA-2048 key pair generation
  • AES-256-CBC file encryption / decryption
  • RSA-OAEP key wrapping (encrypts the AES session key)
  • SHA-256 cryptographic hashing for integrity
  • RSA-PSS digital signatures for sender authentication
  • Tamper simulation endpoint for demonstration
"""

import os
import json
import base64
import hashlib
import uuid
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# In-memory store for generated keys  { username -> { "private": pem, "public": pem } }
key_store: dict[str, dict[str, str]] = {}

# In-memory store for encrypted bundles  { bundle_id -> { ... } }
bundle_store: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    """Base64-encode bytes → string."""
    return base64.b64encode(data).decode("utf-8")


def _b64d(text: str) -> bytes:
    """Base64-decode string → bytes."""
    return base64.b64decode(text)


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API — Key generation
# ---------------------------------------------------------------------------
@app.route("/api/generate-keys", methods=["POST"])
def generate_keys():
    """Generate an RSA-2048 key pair for a named user."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "Username is required"}), 400

    key = RSA.generate(2048)
    private_pem = key.export_key().decode()
    public_pem = key.publickey().export_key().decode()

    key_store[username] = {"private": private_pem, "public": public_pem}

    # Persist to disk as well
    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "w") as f:
        f.write(private_pem)
    with open(os.path.join(KEYS_DIR, f"{username}_public.pem"), "w") as f:
        f.write(public_pem)

    return jsonify({
        "message": f"RSA-2048 key pair generated for '{username}'",
        "public_key": public_pem,
        "private_key_preview": private_pem[:80] + "…",
        "key_size": 2048,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — Encrypt (sender side)
# ---------------------------------------------------------------------------
@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    """
    Encrypt a file for a receiver.

    Expects multipart form:
      • file          – the file to encrypt
      • sender        – username of sender (must have keys)
      • receiver      – username of receiver (must have keys)
    """
    file = request.files.get("file")
    sender = request.form.get("sender", "").strip()
    receiver = request.form.get("receiver", "").strip()

    if not file or not sender or not receiver:
        return jsonify({"error": "file, sender, and receiver are all required"}), 400
    if sender not in key_store:
        return jsonify({"error": f"No keys found for sender '{sender}'. Generate keys first."}), 400
    if receiver not in key_store:
        return jsonify({"error": f"No keys found for receiver '{receiver}'. Generate keys first."}), 400

    plaintext = file.read()
    original_filename = file.filename
    original_size = len(plaintext)

    # 1) SHA-256 hash of original file
    file_hash = hashlib.sha256(plaintext).hexdigest()

    # 2) Digital signature (sender signs the hash with their private key)
    sender_private_key = RSA.import_key(key_store[sender]["private"])
    h = SHA256.new(plaintext)
    signature = pkcs1_15.new(sender_private_key).sign(h)

    # 3) AES-256-CBC encryption
    aes_key = get_random_bytes(32)       # 256-bit key
    iv = get_random_bytes(AES.block_size) # 16-byte IV
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    # 4) RSA-OAEP: encrypt the AES key with receiver's public key
    receiver_public_key = RSA.import_key(key_store[receiver]["public"])
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 5) Build the bundle
    bundle_id = str(uuid.uuid4())[:8]
    bundle = {
        "bundle_id": bundle_id,
        "original_filename": original_filename,
        "original_size": original_size,
        "sender": sender,
        "receiver": receiver,
        "file_hash_sha256": file_hash,
        "signature": _b64e(signature),
        "sender_public_key": key_store[sender]["public"],
        "encrypted_aes_key": _b64e(encrypted_aes_key),
        "iv": _b64e(iv),
        "ciphertext": _b64e(ciphertext),
        "encrypted_size": len(ciphertext),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    bundle_store[bundle_id] = bundle

    return jsonify({
        "message": "File encrypted and signed successfully",
        "bundle_id": bundle_id,
        "original_filename": original_filename,
        "original_size": original_size,
        "encrypted_size": len(ciphertext),
        "file_hash_sha256": file_hash,
        "signature_preview": _b64e(signature)[:60] + "…",
        "aes_key_encrypted": True,
        "algorithm_suite": "AES-256-CBC + RSA-2048-OAEP + SHA-256 + RSA-PKCS1v15-Sign",
        "timestamp": bundle["timestamp"],
    })


# ---------------------------------------------------------------------------
# API — Decrypt & verify (receiver side)
# ---------------------------------------------------------------------------
@app.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    """
    Decrypt a bundle and verify integrity + sender authenticity.

    Expects JSON: { "bundle_id": "..." }
    """
    data = request.get_json(force=True)
    bundle_id = data.get("bundle_id", "").strip()

    if bundle_id not in bundle_store:
        return jsonify({"error": f"Bundle '{bundle_id}' not found"}), 404

    bundle = bundle_store[bundle_id]
    receiver = bundle["receiver"]

    # 1) RSA-OAEP: decrypt the AES key
    receiver_private_key = RSA.import_key(key_store[receiver]["private"])
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    try:
        aes_key = cipher_rsa.decrypt(_b64d(bundle["encrypted_aes_key"]))
    except (ValueError, KeyError):
        return jsonify({
            "error": "Failed to decrypt AES key — wrong receiver key?",
            "integrity": "UNKNOWN",
            "authentication": "UNKNOWN",
        }), 400

    # 2) AES-256-CBC: decrypt the file
    iv = _b64d(bundle["iv"])
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher_aes.decrypt(_b64d(bundle["ciphertext"])), AES.block_size)
    except (ValueError, KeyError):
        return jsonify({
            "error": "AES decryption failed — data may be corrupted or tampered",
            "tamper_detected": True,
            "integrity": "FAILED",
            "authentication": "UNKNOWN",
        }), 400

    # 3) SHA-256: recompute hash
    computed_hash = hashlib.sha256(plaintext).hexdigest()
    original_hash = bundle["file_hash_sha256"]
    hash_match = computed_hash == original_hash

    # 4) Verify digital signature
    sender_public_key = RSA.import_key(bundle["sender_public_key"])
    h = SHA256.new(plaintext)
    try:
        pkcs1_15.new(sender_public_key).verify(h, _b64d(bundle["signature"]))
        signature_valid = True
    except (ValueError, TypeError):
        signature_valid = False

    tamper_detected = not hash_match or not signature_valid

    # Decode plaintext for preview (if text-like)
    try:
        decoded_preview = plaintext[:500].decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        decoded_preview = f"[Binary file — {len(plaintext)} bytes]"
        is_text = False

    return jsonify({
        "message": "Decryption complete",
        "bundle_id": bundle_id,
        "original_filename": bundle["original_filename"],
        "decrypted_size": len(plaintext),
        "original_hash": original_hash,
        "computed_hash": computed_hash,
        "hash_match": hash_match,
        "signature_valid": signature_valid,
        "tamper_detected": tamper_detected,
        "integrity": "PASSED ✅" if hash_match else "FAILED ❌",
        "authentication": "VERIFIED ✅" if signature_valid else "FAILED ❌",
        "overall_status": "TRUSTED ✅" if not tamper_detected else "REJECTED ❌ — TAMPER DETECTED",
        "file_preview": decoded_preview,
        "is_text": is_text,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — Simulate tampering
# ---------------------------------------------------------------------------
@app.route("/api/tamper", methods=["POST"])
def tamper_bundle():
    """
    Simulate an attacker modifying the encrypted ciphertext.

    Expects JSON: { "bundle_id": "...", "tamper_type": "ciphertext" | "signature" | "hash" }
    """
    data = request.get_json(force=True)
    bundle_id = data.get("bundle_id", "").strip()
    tamper_type = data.get("tamper_type", "ciphertext")

    if bundle_id not in bundle_store:
        return jsonify({"error": f"Bundle '{bundle_id}' not found"}), 404

    bundle = bundle_store[bundle_id]

    if tamper_type == "ciphertext":
        # Flip some bytes in the ciphertext
        ct = bytearray(_b64d(bundle["ciphertext"]))
        for i in range(min(16, len(ct))):
            ct[i] ^= 0xFF
        bundle["ciphertext"] = _b64e(bytes(ct))
        detail = "Flipped first 16 bytes of ciphertext"

    elif tamper_type == "signature":
        # Corrupt the signature
        sig = bytearray(_b64d(bundle["signature"]))
        sig[0] ^= 0xFF
        bundle["signature"] = _b64e(bytes(sig))
        detail = "Corrupted first byte of digital signature"

    elif tamper_type == "hash":
        # Alter the stored hash
        bundle["file_hash_sha256"] = "0" * 64
        detail = "Replaced stored SHA-256 hash with zeros"
    else:
        return jsonify({"error": "tamper_type must be 'ciphertext', 'signature', or 'hash'"}), 400

    return jsonify({
        "message": f"⚠️ Bundle '{bundle_id}' has been tampered with!",
        "tamper_type": tamper_type,
        "detail": detail,
        "bundle_id": bundle_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — List bundles
# ---------------------------------------------------------------------------
@app.route("/api/bundles", methods=["GET"])
def list_bundles():
    """Return a summary of all encrypted bundles."""
    summaries = []
    for bid, b in bundle_store.items():
        summaries.append({
            "bundle_id": bid,
            "original_filename": b["original_filename"],
            "sender": b["sender"],
            "receiver": b["receiver"],
            "original_size": b["original_size"],
            "encrypted_size": b["encrypted_size"],
            "timestamp": b["timestamp"],
        })
    return jsonify(summaries)


# ---------------------------------------------------------------------------
# API — List users with keys
# ---------------------------------------------------------------------------
@app.route("/api/users", methods=["GET"])
def list_users():
    """Return list of users who have generated key pairs."""
    users = []
    for username, keys in key_store.items():
        users.append({
            "username": username,
            "has_keys": True,
            "public_key_preview": keys["public"][:80] + "…",
        })
    return jsonify(users)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n[*] CryptoShield Server Starting...")
    print("    AES-256-CBC | RSA-2048-OAEP | SHA-256 | RSA Digital Signatures")
    print("    http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
