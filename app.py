from pki_service import pki_engine
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
  ------- NEW FEATURES -------
  • Image Encryption with Visual Preview (pixel-level AES)
  • LSB Steganography — hide/reveal secrets inside images
  • Cipher Algorithm Playground (AES, DES, Caesar, Vigenère)
  • QR Code Secret Vault (encrypt → QR Code → decode)
  • Digital PKI Simulator (CA, certificates, chain of trust)
"""

import os
import io
import json
import base64
import hashlib
import uuid
import struct
import math
import datetime as dt
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import qrcode
from PIL import Image
import numpy as np

# Cryptography for X.509 PKI
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes as crypt_hashes, serialization as crypt_serial
from cryptography.hazmat.primitives.asymmetric import rsa as crypt_rsa, padding as crypt_padding

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
KEYS_DIR   = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(KEYS_DIR,   exist_ok=True)

# In-memory stores
key_store:    dict[str, dict[str, str]] = {}
bundle_store: dict[str, dict]          = {}
cert_store:   dict[str, dict]          = {}   # { cn -> { cert_pem, key_pem, issued_by } }
ca_store:     dict[str, dict]          = {}   # { cn -> { cert_pem, key_pem } } — CA certs


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def _b64d(text: str) -> bytes:
    return base64.b64decode(text)

def _img_to_b64(img: Image.Image, fmt: str = "PNG") -> str:
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return base64.b64encode(buf.getvalue()).decode()

def _caesar_encrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)

def _vigenere_encrypt(text: str, key: str) -> str:
    key = key.upper()
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


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
    public_pem  = key.publickey().export_key().decode()

    key_store[username] = {"private": private_pem, "public": public_pem}

    with open(os.path.join(KEYS_DIR, f"{username}_private.pem"), "w") as f:
        f.write(private_pem)
    with open(os.path.join(KEYS_DIR, f"{username}_public.pem"), "w") as f:
        f.write(public_pem)

    return jsonify({
        "message":          f"RSA-2048 key pair generated for '{username}'",
        "public_key":        public_pem,
        "private_key_preview": private_pem[:80] + "…",
        "key_size":          2048,
        "timestamp":         datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — Encrypt (sender side)
# ---------------------------------------------------------------------------
@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    file     = request.files.get("file")
    sender   = request.form.get("sender",   "").strip()
    receiver = request.form.get("receiver", "").strip()

    if not file or not sender or not receiver:
        return jsonify({"error": "file, sender, and receiver are all required"}), 400
    if sender not in key_store:
        return jsonify({"error": f"No keys found for sender '{sender}'. Generate keys first."}), 400
    if receiver not in key_store:
        return jsonify({"error": f"No keys found for receiver '{receiver}'. Generate keys first."}), 400

    plaintext         = file.read()
    original_filename = file.filename
    original_size     = len(plaintext)

    file_hash = hashlib.sha256(plaintext).hexdigest()

    sender_private_key = RSA.import_key(key_store[sender]["private"])
    h = SHA256.new(plaintext)
    signature = pkcs1_15.new(sender_private_key).sign(h)

    aes_key   = get_random_bytes(32)
    iv        = get_random_bytes(AES.block_size)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    receiver_public_key = RSA.import_key(key_store[receiver]["public"])
    cipher_rsa         = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key  = cipher_rsa.encrypt(aes_key)

    bundle_id = str(uuid.uuid4())[:8]
    bundle = {
        "bundle_id":         bundle_id,
        "original_filename": original_filename,
        "original_size":     original_size,
        "sender":            sender,
        "receiver":          receiver,
        "file_hash_sha256":  file_hash,
        "signature":         _b64e(signature),
        "sender_public_key": key_store[sender]["public"],
        "encrypted_aes_key": _b64e(encrypted_aes_key),
        "iv":                _b64e(iv),
        "ciphertext":        _b64e(ciphertext),
        "encrypted_size":    len(ciphertext),
        "timestamp":         datetime.utcnow().isoformat() + "Z",
    }
    bundle_store[bundle_id] = bundle

    return jsonify({
        "message":          "File encrypted and signed successfully",
        "bundle_id":         bundle_id,
        "original_filename": original_filename,
        "original_size":     original_size,
        "encrypted_size":    len(ciphertext),
        "file_hash_sha256":  file_hash,
        "signature_preview": _b64e(signature)[:60] + "…",
        "aes_key_encrypted": True,
        "algorithm_suite":   "AES-256-CBC + RSA-2048-OAEP + SHA-256 + RSA-PKCS1v15-Sign",
        "timestamp":         bundle["timestamp"],
    })


# ---------------------------------------------------------------------------
# API — Decrypt & verify (receiver side)
# ---------------------------------------------------------------------------
@app.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    data      = request.get_json(force=True)
    bundle_id = data.get("bundle_id", "").strip()

    if bundle_id not in bundle_store:
        return jsonify({"error": f"Bundle '{bundle_id}' not found"}), 404

    bundle   = bundle_store[bundle_id]
    receiver = bundle["receiver"]

    receiver_private_key = RSA.import_key(key_store[receiver]["private"])
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    try:
        aes_key = cipher_rsa.decrypt(_b64d(bundle["encrypted_aes_key"]))
    except (ValueError, KeyError):
        return jsonify({"error": "Failed to decrypt AES key — wrong receiver key?",
                        "integrity": "UNKNOWN", "authentication": "UNKNOWN"}), 400

    iv = _b64d(bundle["iv"])
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher_aes.decrypt(_b64d(bundle["ciphertext"])), AES.block_size)
    except (ValueError, KeyError):
        return jsonify({"error": "AES decryption failed — data may be corrupted or tampered",
                        "tamper_detected": True, "integrity": "FAILED", "authentication": "UNKNOWN"}), 400

    computed_hash = hashlib.sha256(plaintext).hexdigest()
    original_hash = bundle["file_hash_sha256"]
    hash_match    = computed_hash == original_hash

    sender_public_key = RSA.import_key(bundle["sender_public_key"])
    h = SHA256.new(plaintext)
    try:
        pkcs1_15.new(sender_public_key).verify(h, _b64d(bundle["signature"]))
        signature_valid = True
    except (ValueError, TypeError):
        signature_valid = False

    tamper_detected = not hash_match or not signature_valid

    try:
        decoded_preview = plaintext[:500].decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        decoded_preview = f"[Binary file — {len(plaintext)} bytes]"
        is_text = False

    return jsonify({
        "message":           "Decryption complete",
        "bundle_id":          bundle_id,
        "original_filename":  bundle["original_filename"],
        "decrypted_size":     len(plaintext),
        "original_hash":      original_hash,
        "computed_hash":      computed_hash,
        "hash_match":         hash_match,
        "signature_valid":    signature_valid,
        "tamper_detected":    tamper_detected,
        "integrity":          "PASSED ✅" if hash_match else "FAILED ❌",
        "authentication":     "VERIFIED ✅" if signature_valid else "FAILED ❌",
        "overall_status":     "TRUSTED ✅" if not tamper_detected else "REJECTED ❌ — TAMPER DETECTED",
        "file_preview":       decoded_preview,
        "is_text":            is_text,
        "timestamp":          datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — Simulate tampering
# ---------------------------------------------------------------------------
@app.route("/api/tamper", methods=["POST"])
def tamper_bundle():
    data       = request.get_json(force=True)
    bundle_id  = data.get("bundle_id",   "").strip()
    tamper_type = data.get("tamper_type", "ciphertext")

    if bundle_id not in bundle_store:
        return jsonify({"error": f"Bundle '{bundle_id}' not found"}), 404

    bundle = bundle_store[bundle_id]

    if tamper_type == "ciphertext":
        ct = bytearray(_b64d(bundle["ciphertext"]))
        for i in range(min(16, len(ct))): ct[i] ^= 0xFF
        bundle["ciphertext"] = _b64e(bytes(ct))
        detail = "Flipped first 16 bytes of ciphertext"
    elif tamper_type == "signature":
        sig = bytearray(_b64d(bundle["signature"]))
        sig[0] ^= 0xFF
        bundle["signature"] = _b64e(bytes(sig))
        detail = "Corrupted first byte of digital signature"
    elif tamper_type == "hash":
        bundle["file_hash_sha256"] = "0" * 64
        detail = "Replaced stored SHA-256 hash with zeros"
    else:
        return jsonify({"error": "tamper_type must be 'ciphertext', 'signature', or 'hash'"}), 400

    return jsonify({
        "message":     f"⚠️ Bundle '{bundle_id}' has been tampered with!",
        "tamper_type":  tamper_type,
        "detail":       detail,
        "bundle_id":    bundle_id,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# API — List bundles
# ---------------------------------------------------------------------------
@app.route("/api/bundles", methods=["GET"])
def list_bundles():
    summaries = []
    for bid, b in bundle_store.items():
        summaries.append({
            "bundle_id":         bid,
            "original_filename": b["original_filename"],
            "sender":            b["sender"],
            "receiver":          b["receiver"],
            "original_size":     b["original_size"],
            "encrypted_size":    b["encrypted_size"],
            "timestamp":         b["timestamp"],
        })
    return jsonify(summaries)


# ---------------------------------------------------------------------------
# API — List users with keys
# ---------------------------------------------------------------------------
@app.route("/api/users", methods=["GET"])
def list_users():
    users = []
    for username, keys in key_store.items():
        users.append({
            "username":            username,
            "has_keys":            True,
            "public_key_preview":  keys["public"][:80] + "…",
        })
    return jsonify(users)


# ===========================================================================
# NEW FEATURE 1 — Image Encryption with Visual Preview & ECB vs CBC Analysis
# ===========================================================================
def _calc_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy of raw byte sequence (0 to 8 bits/byte)."""
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    nonzero = counts[counts > 0]
    total = len(arr)
    probs = nonzero / total
    return float(-np.sum(probs * np.log2(probs)))


@app.route("/api/image-encrypt", methods=["POST"])
def image_encrypt():
    """
    Encrypts an image using both AES-256-CBC and AES-256-ECB.
    Computes Shannon entropy for leak analysis.
    """
    file = request.files.get("image")
    if not file:
        return jsonify({"error": "No image file provided"}), 400

    try:
        img = Image.open(file).convert("RGB")
    except Exception:
        return jsonify({"error": "Invalid image file"}), 400

    original_b64 = _img_to_b64(img)
    width, height = img.size

    raw_pixels = img.tobytes()
    aes_key    = get_random_bytes(32)
    iv         = get_random_bytes(16)

    # CBC Encryption
    cipher_cbc = AES.new(aes_key, AES.MODE_CBC, iv)
    padded     = pad(raw_pixels, AES.block_size)
    ct_cbc     = cipher_cbc.encrypt(padded)

    # ECB Encryption (demonstrates electronic codebook pixel correlation)
    cipher_ecb = AES.new(aes_key, AES.MODE_ECB)
    ct_ecb     = cipher_ecb.encrypt(padded)

    # CBC Noise Image
    noise_cbc_bytes = ct_cbc[:width * height * 3]
    noise_cbc_arr   = np.frombuffer(noise_cbc_bytes, dtype=np.uint8).reshape((height, width, 3))
    noise_cbc_img   = Image.fromarray(noise_cbc_arr, "RGB")
    noise_cbc_b64   = _img_to_b64(noise_cbc_img)

    # ECB Noise Image
    noise_ecb_bytes = ct_ecb[:width * height * 3]
    noise_ecb_arr   = np.frombuffer(noise_ecb_bytes, dtype=np.uint8).reshape((height, width, 3))
    noise_ecb_img   = Image.fromarray(noise_ecb_arr, "RGB")
    noise_ecb_b64   = _img_to_b64(noise_ecb_img)

    entropy_orig = round(_calc_entropy(raw_pixels), 4)
    entropy_cbc  = round(_calc_entropy(ct_cbc), 4)
    entropy_ecb  = round(_calc_entropy(ct_ecb), 4)

    return jsonify({
        "original_image":       original_b64,
        "encrypted_image":      noise_cbc_b64,
        "encrypted_image_cbc":  noise_cbc_b64,
        "encrypted_image_ecb":  noise_ecb_b64,
        "entropy_original":     entropy_orig,
        "entropy_cbc":          entropy_cbc,
        "entropy_ecb":          entropy_ecb,
        "width":                width,
        "height":               height,
        "aes_key":              _b64e(aes_key),
        "iv":                   _b64e(iv),
        "ciphertext":           _b64e(ct_cbc),
        "ciphertext_ecb":       _b64e(ct_ecb),
        "original_size":        len(raw_pixels),
        "encrypted_size":       len(ct_cbc),
        "algorithm":            "AES-256-CBC pixel encryption",
    })


@app.route("/api/image-decrypt", methods=["POST"])
def image_decrypt():
    """
    Decrypts an encrypted image using the provided AES key + IV.
    """
    data = request.get_json(force=True)
    try:
        aes_key    = _b64d(data["aes_key"])
        iv         = _b64d(data.get("iv", "")) if data.get("iv") else b""
        ciphertext = _b64d(data["ciphertext"])
        width      = int(data["width"])
        height     = int(data["height"])
        mode       = data.get("mode", "CBC").upper()
    except (KeyError, Exception) as e:
        return jsonify({"error": f"Missing or invalid parameters: {e}"}), 400

    if mode == "ECB":
        cipher = AES.new(aes_key, AES.MODE_ECB)
    else:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    img       = Image.frombytes("RGB", (width, height), plaintext)
    decrypted_b64 = _img_to_b64(img)

    return jsonify({
        "decrypted_image": decrypted_b64,
        "message":         "Image decrypted successfully",
        "mode_used":       mode,
    })


# ===========================================================================
# NEW FEATURE 2 — Steganography Lab (LSB)
# ===========================================================================
@app.route("/api/steg-hide", methods=["POST"])
def steg_hide():
    """
    Hides a secret message inside an image using LSB (Least Significant Bit) steganography.
    The last bit of each R, G, B channel encodes one bit of the message.
    """
    file    = request.files.get("image")
    message = request.form.get("message", "")

    if not file:
        return jsonify({"error": "No image file provided"}), 400
    if not message:
        return jsonify({"error": "No message provided"}), 400

    try:
        img = Image.open(file).convert("RGB")
    except Exception:
        return jsonify({"error": "Invalid image file"}), 400

    # Encode message length + message as bytes with a sentinel
    msg_bytes  = message.encode("utf-8")
    # 4 bytes for length, then message
    header     = struct.pack(">I", len(msg_bytes))
    payload    = header + msg_bytes

    pixels     = list(img.getdata())
    max_bits   = len(pixels) * 3   # 1 bit per channel
    max_bytes  = max_bits // 8

    if len(payload) > max_bytes:
        return jsonify({"error": f"Message too long for this image. Max {max_bytes - 4} bytes."}), 400

    # Embed bits
    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    new_pixels = []
    bit_idx    = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & ~1) | bits[bit_idx];  bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | bits[bit_idx];  bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | bits[bit_idx];  bit_idx += 1
        new_pixels.append((r, g, b))

    steg_img = Image.new("RGB", img.size)
    steg_img.putdata(new_pixels)

    original_b64 = _img_to_b64(img)
    steg_b64     = _img_to_b64(steg_img)

    return jsonify({
        "original_image":    original_b64,
        "steg_image":        steg_b64,
        "message_length":    len(msg_bytes),
        "bits_used":         len(bits),
        "capacity_bytes":    max_bytes - 4,
        "method":            "LSB (Least Significant Bit) Steganography",
        "note":              "The two images look visually identical — the secret is invisible to the naked eye.",
    })


@app.route("/api/steg-reveal", methods=["POST"])
def steg_reveal():
    """Extract hidden message from an LSB-steganography image."""
    file = request.files.get("image")
    if not file:
        return jsonify({"error": "No image file provided"}), 400

    try:
        img = Image.open(file).convert("RGB")
    except Exception:
        return jsonify({"error": "Invalid image file"}), 400

    pixels = list(img.getdata())
    raw_bits = []
    for r, g, b in pixels:
        raw_bits += [(r & 1), (g & 1), (b & 1)]

    def bits_to_bytes(bits_list):
        result = []
        for i in range(0, len(bits_list) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits_list[i + j]
            result.append(byte)
        return bytes(result)

    raw = bits_to_bytes(raw_bits)
    if len(raw) < 4:
        return jsonify({"error": "Image does not contain a hidden message (too small)"}), 400

    msg_len = struct.unpack(">I", raw[:4])[0]
    if msg_len == 0 or msg_len > len(raw) - 4:
        return jsonify({"error": "No valid hidden message found in this image"}), 400

    try:
        message = raw[4:4 + msg_len].decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "Hidden data found but could not decode as UTF-8 text"}), 400

    return jsonify({
        "message":        message,
        "message_length": msg_len,
        "method":         "LSB (Least Significant Bit) Steganography",
    })


# ===========================================================================
# NEW FEATURE 3 — Cipher Algorithm Playground
# ===========================================================================
@app.route("/api/cipher-playground", methods=["POST"])
def cipher_playground():
    """
    Encrypt the same plaintext with multiple algorithms and return side-by-side results.
    Algorithms: AES-256-CBC, DES-CBC, Caesar (shift 13), Vigenère (key='CRYPTO')
    """
    data      = request.get_json(force=True)
    plaintext = data.get("text", "").strip()
    caesar_shift  = int(data.get("caesar_shift",  13))
    vigenere_key  = data.get("vigenere_key", "CRYPTO").upper() or "CRYPTO"

    if not plaintext:
        return jsonify({"error": "Text is required"}), 400
    if len(plaintext) > 2000:
        return jsonify({"error": "Text too long (max 2000 chars)"}), 400

    results = {}
    pt_bytes = plaintext.encode("utf-8")

    # --- AES-256-CBC ---
    aes_key = get_random_bytes(32)
    aes_iv  = get_random_bytes(16)
    aes_ct  = AES.new(aes_key, AES.MODE_CBC, aes_iv).encrypt(pad(pt_bytes, 16))
    results["aes256"] = {
        "name":        "AES-256-CBC",
        "ciphertext":  _b64e(aes_ct),
        "hex":         aes_ct.hex(),
        "key_b64":     _b64e(aes_key),
        "iv_b64":      _b64e(aes_iv),
        "key_bits":    256,
        "block_size":  128,
        "output_len":  len(aes_ct),
        "type":        "Symmetric Block Cipher (modern)",
        "security":    "strong",
    }

    # --- DES-CBC (56-bit — deliberately weak) ---
    des_key = get_random_bytes(8)
    des_iv  = get_random_bytes(8)
    des_ct  = DES.new(des_key, DES.MODE_CBC, des_iv).encrypt(pad(pt_bytes, 8))
    results["des"] = {
        "name":        "DES-CBC",
        "ciphertext":  _b64e(des_ct),
        "hex":         des_ct.hex(),
        "key_b64":     _b64e(des_key),
        "iv_b64":      _b64e(des_iv),
        "key_bits":    56,
        "block_size":  64,
        "output_len":  len(des_ct),
        "type":        "Symmetric Block Cipher (legacy/broken)",
        "security":    "weak",
        "warning":     "DES is considered broken. Exhaustive key search (brute force) is feasible with modern hardware.",
    }

    # --- Caesar Cipher ---
    caesar_ct = _caesar_encrypt(plaintext, caesar_shift)
    results["caesar"] = {
        "name":        f"Caesar Cipher (shift={caesar_shift})",
        "ciphertext":  caesar_ct,
        "shift":       caesar_shift,
        "type":        "Classical Substitution Cipher",
        "security":    "none",
        "warning":     "Only 25 possible shifts — trivially broken by brute force or frequency analysis.",
    }

    # --- Vigenère Cipher ---
    vigenere_ct = _vigenere_encrypt(plaintext, vigenere_key)
    results["vigenere"] = {
        "name":       f"Vigenère Cipher (key='{vigenere_key}')",
        "ciphertext":  vigenere_ct,
        "key":         vigenere_key,
        "type":        "Classical Polyalphabetic Cipher",
        "security":    "very_weak",
        "warning":     "Breakable using Kasiski examination or Index of Coincidence analysis.",
    }

    # --- SHA-256 Hash (for comparison) ---
    sha_hash = hashlib.sha256(pt_bytes).hexdigest()
    sha1_hash = hashlib.sha1(pt_bytes).hexdigest()
    md5_hash  = hashlib.md5(pt_bytes).hexdigest()
    results["hashes"] = {
        "sha256": sha_hash,
        "sha1":   sha1_hash,
        "md5":    md5_hash,
    }

    return jsonify({
        "original_text":   plaintext,
        "original_length": len(plaintext),
        "results":         results,
        "timestamp":       datetime.utcnow().isoformat() + "Z",
    })


# ===========================================================================
# NEW FEATURE 4 — QR Code Secret Vault
# ===========================================================================
@app.route("/api/qr-encrypt", methods=["POST"])
def qr_encrypt():
    """
    Encrypt a message with AES-256, then encode the ciphertext into a QR code image.
    Returns the QR code as base64 PNG and the decryption key.
    """
    data    = request.get_json(force=True)
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400
    if len(message) > 500:
        return jsonify({"error": "Message too long (max 500 chars for QR compatibility)"}), 400

    aes_key   = get_random_bytes(32)
    iv        = get_random_bytes(16)
    cipher    = AES.new(aes_key, AES.MODE_CBC, iv)
    ct        = cipher.encrypt(pad(message.encode("utf-8"), 16))

    # Pack IV + ciphertext into base64 for QR payload
    payload   = _b64e(iv + ct)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    qr_img     = qr.make_image(fill_color="#06b6d4", back_color="#06080f")
    qr_img_pil = qr_img.convert("RGB")
    qr_b64     = _img_to_b64(qr_img_pil)

    return jsonify({
        "qr_image":        qr_b64,
        "aes_key":         _b64e(aes_key),
        "payload_b64":     payload,
        "message_length":  len(message),
        "algorithm":       "AES-256-CBC",
        "note":            "Share the QR code publicly — only the holder of the AES key can decrypt it.",
    })


@app.route("/api/qr-decrypt", methods=["POST"])
def qr_decrypt():
    """
    Decrypt a QR-encoded AES-256 message given the payload (base64 IV+CT) and AES key.
    """
    data    = request.get_json(force=True)
    payload = data.get("payload_b64", "").strip()
    aes_key_b64 = data.get("aes_key", "").strip()

    if not payload or not aes_key_b64:
        return jsonify({"error": "payload_b64 and aes_key are required"}), 400

    try:
        raw     = _b64d(payload)
        iv      = raw[:16]
        ct      = raw[16:]
        aes_key = _b64d(aes_key_b64)
        cipher  = AES.new(aes_key, AES.MODE_CBC, iv)
        pt      = unpad(cipher.decrypt(ct), 16).decode("utf-8")
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

    return jsonify({
        "message":   pt,
        "algorithm": "AES-256-CBC",
    })


# ===========================================================================
# NEW FEATURE 5 — Digital PKI Simulator (CA + Certificate Issuance)
# ===========================================================================
# ---------------------------------------------------------------------------
# PKI Simulator Routes
# ---------------------------------------------------------------------------
@app.route("/api/pki/create-ca", methods=["POST"])
def pki_create_ca():
    req = request.get_json(force=True) or {}
    name = req.get("cn", "").strip()
    org = req.get("org", "CryptoShield").strip()
    country = req.get("country", "IN").strip()
    if not name:
        return jsonify({"error": "Common Name (cn) is required"}), 400
    try:
        cert_pem = pki_engine.build_root_ca(name, org, country)
        return jsonify({
            "message": f"Root CA '{name}' created successfully",
            "ca_name": name,
            "cert_pem": cert_pem,
            "valid_years": 10,
            "is_ca": True,
            "subject": f"CN={name}, O={org}, C={country}",
            "issuer": f"CN={name} (Self-Signed)",
            "signature_algo": "SHA256withRSA",
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/pki/issue-cert", methods=["POST"])
def pki_issue_cert():
    req = request.get_json(force=True) or {}
    ca_name = req.get("ca_name", "").strip()
    entity_cn = req.get("entity_cn", "").strip()
    org = req.get("org", "CryptoShield Inc").strip()
    country = req.get("country", "IN").strip()
    if not ca_name or not entity_cn:
        return jsonify({"error": "ca_name and entity_cn are required"}), 400
    try:
        cert_pem = pki_engine.issue_leaf_cert(ca_name, entity_cn, org, country)
        rec = pki_engine.cert_records[entity_cn]
        return jsonify({
            "message": f"Certificate issued for '{entity_cn}' by CA '{ca_name}'",
            "entity_cn": entity_cn,
            "issued_by": ca_name,
            "cert_pem": cert_pem,
            "subject": f"CN={entity_cn}, O={org}, C={country}",
            "issuer": f"CN={ca_name}",
            "not_before": rec["valid_from"],
            "not_after": rec["valid_until"],
            "valid_days": 365,
            "signature_algo": "SHA256withRSA",
            "key_usage": "digitalSignature, keyEncipherment",
        })
    except KeyError:
        return jsonify({"error": f"CA '{ca_name}' not found. Create a CA first."}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/pki/verify-cert", methods=["POST"])
def pki_verify_cert():
    req = request.get_json(force=True) or {}
    entity_cn = req.get("entity_cn", "").strip()
    if not entity_cn:
        return jsonify({"error": "entity_cn is required"}), 400
    if entity_cn not in pki_engine.cert_records:
        return jsonify({"error": f"Certificate for '{entity_cn}' not found"}), 404
    is_valid, msg = pki_engine.validate_leaf(entity_cn)
    rec = pki_engine.cert_records[entity_cn]
    return jsonify({
        "entity_cn": entity_cn,
        "issued_by": rec["issued_by"],
        "is_valid": is_valid,
        "status": "VALID ✅" if is_valid else f"INVALID ❌ — {msg}",
        "chain": [entity_cn, rec["issued_by"]],
        "cert_pem": rec["cert_pem"],
    })


@app.route("/api/pki/list", methods=["GET"])
def pki_list():
    return jsonify({
        "cas": list(pki_engine.ca_records.keys()),
        "certs": [{"cn": k, "issued_by": v["issued_by"]} for k, v in pki_engine.cert_records.items()],
    })


# ---------------------------------------------------------------------------
# Educational Deep Dive API Endpoints
# ---------------------------------------------------------------------------
def _compute_rijndael_sbox():
    p = 1
    exp_t = [0] * 256
    log_t = [0] * 256
    for i in range(256):
        exp_t[i] = p
        log_t[p] = i
        p ^= ((p << 1) ^ 0x11B) if (p & 0x80) else (p << 1)
    
    sb = [0] * 256
    sb[0] = 0x63
    for i in range(1, 256):
        inv = exp_t[255 - log_t[i]]
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sb[i] = s & 0xFF
    return sb

_RIJNDAEL_SBOX = _compute_rijndael_sbox()

def _gf_xtime(b):
    shifted = (b << 1) & 0xFF
    return (shifted ^ 0x1B) if (b & 0x80) else shifted

def _gf_mul(a, b):
    if b == 1:
        return a
    elif b == 2:
        return _gf_xtime(a)
    elif b == 3:
        return _gf_xtime(a) ^ a
    return 0

@app.route("/api/edu/aes-trace", methods=["POST"])
def edu_aes_trace():
    req = request.get_json(force=True) or {}
    msg = req.get("text", "SECURITY_LAB2026").encode("utf-8")[:16].ljust(16, b"\x00")
    key = req.get("key", "AES256_SECRET_KEY_EXPLAINED_OK!").encode("utf-8")[:32].ljust(32, b"\x00")
    
    # 1. State & Key Matrices (4x4 column-major order)
    state_matrix = [[hex(msg[r + 4*c])[2:].zfill(2).upper() for c in range(4)] for r in range(4)]
    key_matrix = [[hex(key[r + 4*c])[2:].zfill(2).upper() for c in range(4)] for r in range(4)]
    
    # Step 1: SubBytes using standard Rijndael S-Box + per-byte lookup details
    sbox_matrix = [["00"] * 4 for _ in range(4)]
    sub_bytes_details = {}
    for r in range(4):
        for c in range(4):
            in_b = int(state_matrix[r][c], 16)
            out_b = _RIJNDAEL_SBOX[in_b]
            out_hex = hex(out_b)[2:].zfill(2).upper()
            sbox_matrix[r][c] = out_hex
            row_idx = (in_b >> 4) & 0x0F
            col_idx = in_b & 0x0F
            sub_bytes_details[f"{r}_{c}"] = {
                "row": r, "col": c,
                "input_hex": state_matrix[r][c],
                "output_hex": out_hex,
                "sbox_row": row_idx,
                "sbox_col": col_idx,
                "ascii": chr(in_b) if 32 <= in_b <= 126 else "."
            }

    # Step 2: ShiftRows: Row r cyclically shifts left by r positions
    shift_matrix = [
        sbox_matrix[0][:],
        sbox_matrix[1][1:] + sbox_matrix[1][:1],
        sbox_matrix[2][2:] + sbox_matrix[2][:2],
        sbox_matrix[3][3:] + sbox_matrix[3][:3],
    ]
    shift_rows_details = [
        {"row": 0, "shift": 0, "before": sbox_matrix[0][:], "after": shift_matrix[0][:]},
        {"row": 1, "shift": 1, "before": sbox_matrix[1][:], "after": shift_matrix[1][:]},
        {"row": 2, "shift": 2, "before": sbox_matrix[2][:], "after": shift_matrix[2][:]},
        {"row": 3, "shift": 3, "before": sbox_matrix[3][:], "after": shift_matrix[3][:]},
    ]

    # Step 3: MixColumns using Galois Field GF(2^8) Matrix Multiplication
    # Fixed MDS Circulant Matrix
    MDS = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    mix_matrix = [["00"] * 4 for _ in range(4)]
    mix_columns_details = []

    for c in range(4):
        col_in_ints = [int(shift_matrix[r][c], 16) for r in range(4)]
        col_in_hex = [shift_matrix[r][c] for r in range(4)]
        col_rows_data = []

        for r in range(4):
            coeffs = MDS[r]
            terms = []
            xor_sum = 0
            for k in range(4):
                coeff = coeffs[k]
                b_in = col_in_ints[k]
                term_val = _gf_mul(b_in, coeff)
                xor_sum ^= term_val
                terms.append({
                    "coeff": f"0{coeff}",
                    "byte_in": hex(b_in)[2:].zfill(2).upper(),
                    "term_hex": hex(term_val)[2:].zfill(2).upper(),
                    "overflow_1b": bool((b_in & 0x80) and coeff in (2, 3))
                })
            res_hex = hex(xor_sum)[2:].zfill(2).upper()
            mix_matrix[r][c] = res_hex
            col_rows_data.append({
                "row": r,
                "coeffs": [f"0{x}" for x in coeffs],
                "terms": terms,
                "equation": f"({terms[0]['coeff']} • {terms[0]['byte_in']}) ⊕ ({terms[1]['coeff']} • {terms[1]['byte_in']}) ⊕ ({terms[2]['coeff']} • {terms[2]['byte_in']}) ⊕ ({terms[3]['coeff']} • {terms[3]['byte_in']}) = {terms[0]['term_hex']} ⊕ {terms[1]['term_hex']} ⊕ {terms[2]['term_hex']} ⊕ {terms[3]['term_hex']} = {res_hex}",
                "result_hex": res_hex
            })

        mix_columns_details.append({
            "col": c,
            "col_input": col_in_hex,
            "col_output": [mix_matrix[r][c] for r in range(4)],
            "rows": col_rows_data
        })

    # Step 4: AddRoundKey (Bitwise XOR with round key)
    add_matrix = [["00"] * 4 for _ in range(4)]
    add_round_key_details = {}
    for r in range(4):
        for c in range(4):
            s_val = int(mix_matrix[r][c], 16)
            k_val = int(key_matrix[r][c], 16)
            res_val = s_val ^ k_val
            res_hex = hex(res_val)[2:].zfill(2).upper()
            add_matrix[r][c] = res_hex
            add_round_key_details[f"{r}_{c}"] = {
                "row": r, "col": c,
                "state_hex": mix_matrix[r][c],
                "state_bin": bin(s_val)[2:].zfill(8),
                "key_hex": key_matrix[r][c],
                "key_bin": bin(k_val)[2:].zfill(8),
                "result_hex": res_hex,
                "result_bin": bin(res_val)[2:].zfill(8)
            }

    return jsonify({
        "input_bytes": [hex(b)[2:].zfill(2).upper() for b in msg],
        "state_matrix": state_matrix,
        "key_matrix": key_matrix,
        "sub_bytes_matrix": sbox_matrix,
        "shift_rows_matrix": shift_matrix,
        "mix_columns_matrix": mix_matrix,
        "add_round_key_matrix": add_matrix,
        "sub_bytes_details": sub_bytes_details,
        "shift_rows_details": shift_rows_details,
        "mix_columns_details": mix_columns_details,
        "add_round_key_details": add_round_key_details,
        "rounds_total": 14,
        "key_bits": 256
    })

@app.route("/api/edu/rsa-trace", methods=["POST"])
def edu_rsa_trace():
    req = request.get_json(force=True) or {}
    p = int(req.get("p", 67))
    q = int(req.get("q", 71))
    e = int(req.get("e", 17))
    m = int(req.get("m", 42))

    n = p * q
    phi = (p - 1) * (q - 1)

    # Extended GCD
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    gcd_val, x, _ = egcd(e, phi)
    d = (x % phi + phi) % phi

    c = pow(m, e, n)
    decrypted = pow(c, d, n)

    # Exponentiation trace
    binary_e = bin(e)[2:]
    exp_steps = []
    accum = 1
    for idx, bit in enumerate(binary_e):
        before = accum
        accum = (accum * accum) % n
        act = f"Square: ({before}^2) mod {n} = {accum}"
        if bit == '1':
            before_m = accum
            accum = (accum * m) % n
            act += f" | Multiply: ({before_m} * {m}) mod {n} = {accum}"
        exp_steps.append({"step": idx + 1, "bit": bit, "operation": act, "current_value": accum})

    return jsonify({
        "p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d,
        "gcd_valid": (gcd_val == 1),
        "message": m,
        "ciphertext": c,
        "decrypted": decrypted,
        "verified": (decrypted == m),
        "exp_steps": exp_steps
    })


@app.route("/api/edu/avalanche", methods=["POST"])
def edu_avalanche():
    req = request.get_json(force=True) or {}
    text1 = req.get("text", "CyberSecurity2026")
    if not text1:
        text1 = "CyberSecurity2026"
    
    # Flip exactly 1 bit in the first character
    b1 = bytearray(text1.encode("utf-8"))
    b2 = bytearray(b1)
    b2[0] ^= 0x01
    text2 = bytes(b2).decode("latin-1")

    # Hash comparison
    h1 = hashlib.sha256(b1).hexdigest()
    h2 = hashlib.sha256(b2).hexdigest()

    h1_bits = "".join(f"{int(c, 16):04b}" for c in h1)
    h2_bits = "".join(f"{int(c, 16):04b}" for c in h2)
    diff_count = sum(1 for a, b in zip(h1_bits, h2_bits) if a != b)
    percentage = round((diff_count / 256.0) * 100, 2)

    return jsonify({
        "original_text": text1,
        "modified_text": text2,
        "sha256_1": h1,
        "sha256_2": h2,
        "bits_flipped": diff_count,
        "total_bits": 256,
        "avalanche_percentage": percentage,
        "bit_diff_map": [1 if a != b else 0 for a, b in zip(h1_bits, h2_bits)]
    })


if __name__ == "__main__":
    print("\n[*] CryptoShield Server Starting...")
    print("    AES-256-CBC | RSA-2048-OAEP | SHA-256 | RSA Digital Signatures")
    print("    + Image Encryption | Steganography | Cipher Playground | QR Vault | PKI Simulator")
    print("    http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
