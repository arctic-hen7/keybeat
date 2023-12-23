import requests
import subprocess
import base64
import json

# Creates a proof of life by signing the block index and hash of the latest block on the Bitcoin
# blockchain.
#
# This uses whatever secret key GPG would use by default, for now at least.
def create_proof(message = ""):
    # Get the details of the latest block
    response = requests.get("https://blockchain.info/latestblock")
    block_data = response.json()

    # The proof-of-life packet is just the block's hash, all else can be reconstructed from that
    block_hash = block_data["hash"]
    packet = {
        "block_hash": block_hash,
        "message": message,
    }
    signed_packet = subprocess.run(["gpg", "--sign"], input=json.dumps(packet).encode(), capture_output=True, check=True)
    # Manually convert to base64 to avoid PGP headers which take up room
    proof = base64.b64encode(signed_packet.stdout).decode()

    return proof
