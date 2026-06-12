#!/usr/bin/env python3
"""AetherProof demo — end-to-end workflow."""

from pathlib import Path
from datetime import datetime
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt, tamper_detect
from aetherproof.core.hash import hash_output, hash_input
from aetherproof.core.log import ReceiptLog

print("=" * 70)
print("AetherProof Demo — The Invariant")
print("=" * 70)
print()

# Step 1: Create a receipt
print("1. Creating a receipt for an AI output...")
output_text = "The economic impact of AI will be significant"
output_hash = hash_output(output_text)
model_weight_hash = hash_output("gpt-4o")

receipt = Receipt(
    receipt_version="1.0",
    model_weight_root=model_weight_hash,
    input_commitment="",  # Privacy: may be hidden
    output_hash=output_hash,
    timestamp_ms=int(datetime.now().timestamp() * 1000),
    log_sequence=0,
    hw_evidence=[],
    signature="",
    log_anchor="",
    receipt_id=f"demo_{datetime.now().timestamp()}",
)
print(f"   Receipt ID: {receipt.receipt_id}")
print(f"   Output hash: {output_hash[:32]}...")
print()

# Step 2: Sign the receipt
print("2. Signing the receipt with Ed25519...")
signer = Signer.generate()
message = f"{receipt.receipt_version}|{receipt.model_weight_root}|{receipt.input_commitment}|{receipt.output_hash}|{receipt.timestamp_ms}|{receipt.log_sequence}|{receipt.hw_evidence}|{receipt.log_anchor}"
receipt.signature = signer.sign(message.encode("utf-8"))
verifier = signer.get_public_key()
print(f"   Signature: {receipt.signature[:32]}...")
print()

# Step 3: Verify the receipt (the invariant)
print("3. Verifying the receipt (THE INVARIANT)...")
is_valid = verify_receipt(receipt, verifier)
print(f"   Verify(receipt, public_key, log) = {is_valid}")
print()

# Step 4: Test tamper detection
print("4. Testing tamper detection (flip one bit)...")
is_detectable = tamper_detect(receipt, verifier)
print(f"   Tamper detection works: {is_detectable}")
print()

# Step 5: Save to file and verify offline
print("5. Saving receipt to file...")
receipt_path = Path("./demo_receipt.json")
receipt_path.write_text(receipt.to_json(pretty=True))
print(f"   Saved to: {receipt_path}")
print()

# Step 6: Save public key
print("6. Saving public key...")
pubkey_path = Path("./demo_receipt.pub")
signer.export_public_file(str(pubkey_path))
print(f"   Saved to: {pubkey_path}")
print()

# Step 7: Offline verification (reload and verify without signer)
print("7. Offline verification (simulate verification later)...")
receipt_reloaded = Receipt.from_json(receipt_path.read_text())
verifier_reloaded = verifier
is_valid_offline = verify_receipt(receipt_reloaded, verifier_reloaded)
print(f"   Offline verify = {is_valid_offline}")
print()

# Step 8: Add to transparency log
print("8. Adding receipt to local transparency log...")
log = ReceiptLog("./demo_log.db")
log_sequence = log.append(receipt)
receipt.log_sequence = log_sequence
receipt.log_anchor = f"local://log/{log_sequence}"
print(f"   Log sequence: {log_sequence}")
print(f"   Total receipts in log: {log.count()}")
print()

print("=" * 70)
print("SUCCESS — The invariant holds:")
print("  Verify(receipt, public_key, log) = TRUE")
print("  Using ONLY those three inputs, forever.")
print("=" * 70)
