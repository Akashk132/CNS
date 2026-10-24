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

# OpenSSL for PKI
from OpenSSL import crypto as ssl_crypto

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
# NEW FEATURE 1 — Image Encryption with Visual Preview
# ===========================================================================
@app.route("/api/image-encrypt", methods=["POST"])
def image_encrypt():
    """
    Encrypts an image using AES-256-CBC.
    Returns:
      - original image as base64 PNG
      - 'encrypted noise' image (pixel-level scramble) as base64 PNG
      - encrypted bytes as base64 (for decryption)
      - AES key + IV as base64
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

    # Encrypt raw pixel bytes with AES-256-CBC
    raw_pixels = img.tobytes()       # exactly width*height*3 bytes
    aes_key    = get_random_bytes(32)
    iv         = get_random_bytes(16)
    cipher     = AES.new(aes_key, AES.MODE_CBC, iv)
    padded     = pad(raw_pixels, AES.block_size)
    ciphertext = cipher.encrypt(padded)

    # Build "noise" image from ciphertext bytes (visualize encrypted pixels)
    noise_bytes = ciphertext[:width * height * 3]          # trim to same dimensions
    noise_arr   = np.frombuffer(noise_bytes, dtype=np.uint8).reshape((height, width, 3))
    noise_img   = Image.fromarray(noise_arr, "RGB")
    noise_b64   = _img_to_b64(noise_img)

    return jsonify({
        "original_image":   original_b64,
        "encrypted_image":  noise_b64,
        "width":            width,
        "height":           height,
        "aes_key":          _b64e(aes_key),
        "iv":               _b64e(iv),
        "ciphertext":       _b64e(ciphertext),
        "original_size":    len(raw_pixels),
        "encrypted_size":   len(ciphertext),
        "algorithm":        "AES-256-CBC pixel encryption",
    })


@app.route("/api/image-decrypt", methods=["POST"])
def image_decrypt():
    """
    Decrypts an encrypted image using the provided AES key + IV.
    Returns the restored image as base64 PNG.
    """
    data = request.get_json(force=True)
    try:
        aes_key    = _b64d(data["aes_key"])
        iv         = _b64d(data["iv"])
        ciphertext = _b64d(data["ciphertext"])
        width      = int(data["width"])
        height     = int(data["height"])
    except (KeyError, Exception) as e:
        return jsonify({"error": f"Missing or invalid parameters: {e}"}), 400

    cipher    = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    img       = Image.frombytes("RGB", (width, height), plaintext)
    decrypted_b64 = _img_to_b64(img)

    return jsonify({
        "decrypted_image": decrypted_b64,
        "message":         "Image decrypted successfully",
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
@app.route("/api/pki/create-ca", methods=["POST"])
def pki_create_ca():
    """
    Create a self-signed Root Certificate Authority (CA).
    """
    data = request.get_json(force=True)
    cn   = data.get("cn", "").strip()        # Common Name, e.g. "MyRootCA"
    org  = data.get("org", "CryptoShield").strip()
    country = data.get("country", "IN").strip().upper()[:2]

    if not cn:
        return jsonify({"error": "Common Name (cn) is required"}), 400

    # Generate RSA-2048 key
    pkey = ssl_crypto.PKey()
    pkey.generate_key(ssl_crypto.TYPE_RSA, 2048)

    cert = ssl_crypto.X509()
    cert.get_subject().CN  = cn
    cert.get_subject().O   = org
    cert.get_subject().C   = country
    cert.set_serial_number(int(uuid.uuid4()))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)   # 10 years
    cert.set_issuer(cert.get_subject())                  # self-signed
    cert.set_pubkey(pkey)

    cert.add_extensions([
        ssl_crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        ssl_crypto.X509Extension(b"keyUsage",         True, b"keyCertSign, cRLSign"),
        ssl_crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
    ])
    cert.sign(pkey, "sha256")

    cert_pem = ssl_crypto.dump_certificate(ssl_crypto.FILETYPE_PEM, cert).decode()
    key_pem  = ssl_crypto.dump_privatekey(ssl_crypto.FILETYPE_PEM, pkey).decode()

    ca_store[cn] = {"cert_pem": cert_pem, "key_pem": key_pem}

    return jsonify({
        "message":         f"Root CA '{cn}' created successfully",
        "ca_name":          cn,
        "cert_pem":         cert_pem,
        "valid_years":      10,
        "is_ca":            True,
        "subject":          f"CN={cn}, O={org}, C={country}",
        "issuer":           f"CN={cn} (Self-Signed)",
        "signature_algo":   "SHA256withRSA",
    })


@app.route("/api/pki/issue-cert", methods=["POST"])
def pki_issue_cert():
    """
    Issue a certificate for an entity, signed by an existing CA.
    """
    data   = request.get_json(force=True)
    ca_name  = data.get("ca_name", "").strip()
    entity_cn = data.get("entity_cn", "").strip()
    org       = data.get("org", "CryptoShield Inc").strip()
    country   = data.get("country", "IN").strip().upper()[:2]

    if not ca_name or not entity_cn:
        return jsonify({"error": "ca_name and entity_cn are required"}), 400
    if ca_name not in ca_store:
        return jsonify({"error": f"CA '{ca_name}' not found. Create a CA first."}), 404

    ca_data  = ca_store[ca_name]
    ca_cert  = ssl_crypto.load_certificate(ssl_crypto.FILETYPE_PEM, ca_data["cert_pem"])
    ca_key   = ssl_crypto.load_privatekey(ssl_crypto.FILETYPE_PEM, ca_data["key_pem"])

    # Generate key for the entity
    entity_key = ssl_crypto.PKey()
    entity_key.generate_key(ssl_crypto.TYPE_RSA, 2048)

    cert = ssl_crypto.X509()
    cert.get_subject().CN = entity_cn
    cert.get_subject().O  = org
    cert.get_subject().C  = country
    cert.set_serial_number(int(uuid.uuid4()))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)   # 1 year
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(entity_key)

    cert.add_extensions([
        ssl_crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        ssl_crypto.X509Extension(b"keyUsage",         False, b"digitalSignature, keyEncipherment"),
        ssl_crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth"),
    ])
    cert.sign(ca_key, "sha256")

    cert_pem = ssl_crypto.dump_certificate(ssl_crypto.FILETYPE_PEM, cert).decode()
    key_pem  = ssl_crypto.dump_privatekey(ssl_crypto.FILETYPE_PEM, entity_key).decode()

    cert_store[entity_cn] = {
        "cert_pem":  cert_pem,
        "key_pem":   key_pem,
        "issued_by": ca_name,
    }

    # Build certificate details
    x509 = cert
    not_before = x509.get_notBefore().decode()
    not_after  = x509.get_notAfter().decode()

    return jsonify({
        "message":       f"Certificate issued for '{entity_cn}' by CA '{ca_name}'",
        "entity_cn":      entity_cn,
        "issued_by":      ca_name,
        "cert_pem":       cert_pem,
        "subject":        f"CN={entity_cn}, O={org}, C={country}",
        "issuer":         f"CN={ca_name}",
        "not_before":     not_before,
        "not_after":      not_after,
        "valid_days":     365,
        "signature_algo": "SHA256withRSA",
        "key_usage":      "digitalSignature, keyEncipherment",
    })


@app.route("/api/pki/verify-cert", methods=["POST"])
def pki_verify_cert():
    """
    Verify a certificate against the CA that signed it.
    """
    data       = request.get_json(force=True)
    entity_cn  = data.get("entity_cn", "").strip()

    if not entity_cn:
        return jsonify({"error": "entity_cn is required"}), 400
    if entity_cn not in cert_store:
        return jsonify({"error": f"Certificate for '{entity_cn}' not found"}), 404

    entry    = cert_store[entity_cn]
    ca_name  = entry["issued_by"]

    if ca_name not in ca_store:
        return jsonify({"error": f"Issuing CA '{ca_name}' not found"}), 404

    ca_cert     = ssl_crypto.load_certificate(ssl_crypto.FILETYPE_PEM, ca_store[ca_name]["cert_pem"])
    entity_cert = ssl_crypto.load_certificate(ssl_crypto.FILETYPE_PEM, entry["cert_pem"])

    # Verify the signature
    try:
        store     = ssl_crypto.X509Store()
        store.add_cert(ca_cert)
        ctx = ssl_crypto.X509StoreContext(store, entity_cert)
        ctx.verify_certificate()
        is_valid = True
        status   = "VALID ✅"
    except ssl_crypto.X509StoreContextError as e:
        is_valid = False
        status   = f"INVALID ❌ — {e}"

    return jsonify({
        "entity_cn":   entity_cn,
        "issued_by":   ca_name,
        "is_valid":    is_valid,
        "status":      status,
        "chain":       [entity_cn, ca_name],
        "cert_pem":    entry["cert_pem"],
    })


@app.route("/api/pki/list", methods=["GET"])
def pki_list():
    return jsonify({
        "cas":   list(ca_store.keys()),
        "certs": [{"cn": cn, "issued_by": v["issued_by"]} for cn, v in cert_store.items()],
    })


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n[*] CryptoShield Server Starting...")
    print("    AES-256-CBC | RSA-2048-OAEP | SHA-256 | RSA Digital Signatures")
    print("    + Image Encryption | Steganography | Cipher Playground | QR Vault | PKI Simulator")
    print("    http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
