import io
import json
import base64
from PIL import Image
import app

client = app.app.test_client()

print("=== TEST 1: HOME PAGE ===")
res = client.get("/")
assert res.status_code == 200, f"Home failed: {res.status_code}"
print("GET / passed (200)")

print("\n=== TEST 2: RSA KEY GENERATION ===")
r_alice = client.post("/api/generate-keys", json={"username": "Alice"})
assert r_alice.status_code == 200, f"Alice keygen failed: {r_alice.get_json()}"
r_bob = client.post("/api/generate-keys", json={"username": "Bob"})
assert r_bob.status_code == 200, f"Bob keygen failed: {r_bob.get_json()}"
print("Alice & Bob keys generated successfully")

print("\n=== TEST 3: HYBRID ENCRYPTION & DECRYPTION ===")
test_file = (io.BytesIO(b"Top secret CNS project file content 2026"), "secret.txt")
r_enc = client.post("/api/encrypt", data={"file": test_file, "sender": "Alice", "receiver": "Bob"})
assert r_enc.status_code == 200, f"Encrypt failed: {r_enc.get_json()}"
bundle_id = r_enc.get_json()["bundle_id"]
print("Encrypted successfully, bundle_id:", bundle_id)

r_dec = client.post("/api/decrypt", json={"bundle_id": bundle_id})
assert r_dec.status_code == 200, f"Decrypt failed: {r_dec.get_json()}"
dec_data = r_dec.get_json()
assert dec_data["hash_match"] is True
assert dec_data["signature_valid"] is True
assert dec_data["tamper_detected"] is False
print("Decrypted and verified successfully! Integrity & signature valid.")

print("\n=== TEST 4: TAMPER SIMULATION ===")
r_tamper = client.post("/api/tamper", json={"bundle_id": bundle_id, "tamper_type": "signature"})
assert r_tamper.status_code == 200
r_dec_tampered = client.post("/api/decrypt", json={"bundle_id": bundle_id})
dec_tampered = r_dec_tampered.get_json()
assert dec_tampered["tamper_detected"] is True
print("Tamper detection verified! Corrupted signature rejected.")

print("\n=== TEST 5: IMAGE ENCRYPTION & DECRYPTION ===")
img = Image.new("RGB", (64, 64), color=(255, 100, 50))
buf = io.BytesIO()
img.save(buf, format="PNG")
buf.seek(0)
r_img_enc = client.post("/api/image-encrypt", data={"image": (buf, "test.png")})
assert r_img_enc.status_code == 200, f"Image encrypt failed: {r_img_enc.get_json()}"
img_data = r_img_enc.get_json()
assert "encrypted_image" in img_data
print("Image encrypted. AES key & noise image produced.")

r_img_dec = client.post("/api/image-decrypt", json={
    "aes_key": img_data["aes_key"],
    "iv": img_data["iv"],
    "ciphertext": img_data["ciphertext"],
    "width": img_data["width"],
    "height": img_data["height"]
})
assert r_img_dec.status_code == 200, f"Image decrypt failed: {r_img_dec.get_json()}"
print("Image decrypted back successfully!")

print("\n=== TEST 6: LSB STEGANOGRAPHY (HIDE & REVEAL) ===")
steg_img = Image.new("RGB", (100, 100), color=(120, 200, 80))
s_buf = io.BytesIO()
steg_img.save(s_buf, format="PNG")
s_buf.seek(0)
secret_msg = "CyberSecurity-2026-Project-Key-9988"
r_hide = client.post("/api/steg-hide", data={"image": (s_buf, "carrier.png"), "message": secret_msg})
assert r_hide.status_code == 200, f"Steg hide failed: {r_hide.get_json()}"
steg_b64 = r_hide.get_json()["steg_image"]

steg_bytes = base64.b64decode(steg_b64)
r_reveal = client.post("/api/steg-reveal", data={"image": (io.BytesIO(steg_bytes), "steg.png")})
assert r_reveal.status_code == 200, f"Steg reveal failed: {r_reveal.get_json()}"
revealed = r_reveal.get_json()["message"]
assert revealed == secret_msg
print(f"LSB Steg passed! Hidden message correctly extracted: '{revealed}'")

print("\n=== TEST 7: CIPHER PLAYGROUND ===")
r_play = client.post("/api/cipher-playground", json={"text": "INFORMATION SECURITY LAB", "caesar_shift": 7, "vigenere_key": "CIPHER"})
assert r_play.status_code == 200, f"Playground failed: {r_play.get_json()}"
play_res = r_play.get_json()["results"]
assert "aes256" in play_res and "des" in play_res and "caesar" in play_res and "vigenere" in play_res and "hashes" in play_res
print("Cipher playground passed! AES-256, DES, Caesar, Vigenere, SHA-256 generated.")

print("\n=== TEST 8: QR CODE SECRET VAULT ===")
qr_secret = "VaultAccessCode-777-ALPHA"
r_qr_enc = client.post("/api/qr-encrypt", json={"message": qr_secret})
assert r_qr_enc.status_code == 200, f"QR encrypt failed: {r_qr_enc.get_json()}"
qr_data = r_qr_enc.get_json()
assert "qr_image" in qr_data

r_qr_dec = client.post("/api/qr-decrypt", json={
    "payload_b64": qr_data["payload_b64"],
    "aes_key": qr_data["aes_key"]
})
assert r_qr_dec.status_code == 200, f"QR decrypt failed: {r_qr_dec.get_json()}"
qr_dec_msg = r_qr_dec.get_json()["message"]
assert qr_dec_msg == qr_secret
print(f"QR Vault passed! Decrypted message matches: '{qr_dec_msg}'")

print("\n=== TEST 9: PKI CERTIFICATE SIMULATOR ===")
r_ca = client.post("/api/pki/create-ca", json={"cn": "GlobalTrust Root CA", "org": "CryptoShield Security", "country": "IN"})
assert r_ca.status_code == 200, f"Create CA failed: {r_ca.get_json()}"

r_cert = client.post("/api/pki/issue-cert", json={"ca_name": "GlobalTrust Root CA", "entity_cn": "api.securebank.com", "org": "Secure Bank Inc"})
assert r_cert.status_code == 200, f"Issue cert failed: {r_cert.get_json()}"

r_verify = client.post("/api/pki/verify-cert", json={"entity_cn": "api.securebank.com"})
assert r_verify.status_code == 200, f"Verify cert failed: {r_verify.get_json()}"
assert r_verify.get_json()["is_valid"] is True
print(f"PKI Simulator passed! Chain verified: {r_verify.get_json()['status'].encode('ascii', 'replace').decode()}")

print("\n==============================================")
print("  ALL 9 COMPREHENSIVE TEST SUITES PASSED!     ")
print("==============================================")
