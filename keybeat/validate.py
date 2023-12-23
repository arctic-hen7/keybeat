import requests
import subprocess
import base64
import tempfile
import time
from .utils import KEYBEAT_ARMOURED_HEADER, KEYBEAT_ARMOURED_FOOTER

# Gets the time at which the given proof was made, cryptographically verifying it using
# the given public key.
def get_proof_time(proof, pubkey = None):
    proof = proof.strip()
    # Write the public key to a temporary file so we can use GPG independent of the host
    # keyring
    with tempfile.NamedTemporaryFile(mode="w") as pubkey_file:
        if pubkey: pubkey_file.write(pubkey)
        pubkey_file.flush()

        # Handle headers
        if proof.startswith(KEYBEAT_ARMOURED_HEADER) and proof.endswith(KEYBEAT_ARMOURED_FOOTER):
            proof = proof[len(KEYBEAT_ARMOURED_HEADER):-len(KEYBEAT_ARMOURED_FOOTER)].strip()

        signature_bytes = base64.b64decode(proof)
        sig_args = ["gpg", "--keyring", pubkey_file.name, "--decrypt"] if pubkey else ["gpg", "--decrypt"]
        res = subprocess.run(sig_args, input=signature_bytes, capture_output=True)
        if not res.returncode == 0:
            raise KeybeatError("invalid signature")

        block_hash = res.stdout.decode()
        # Fetch details of the block whose hash we've referenced
        response = requests.get(f"https://blockchain.info/rawblock/{block_hash}")
        block_data = response.json()

        # Sanity check of the hashes and then return the timestamp, that's all we care about
        if not block_hash == block_data["hash"]:
            raise KeybeatError("sanity check failed, retrieved block has incorrect hash")

        proof_time = int(block_data["time"])
        return proof_time

# Validates the given proof using the given public key, additionally ensuring it was within
# `max_age` seconds of the current time.
def proof_is_valid(proof, max_age, pubkey):
    proof_time = get_proof_time(proof, pubkey)

    proof_age = int(time.time()) - proof_time
    return proof_age > 0 and proof_age < max_age
