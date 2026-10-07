#!/usr/bin/env python3
"""Sign exact Agent manifest bytes with a dedicated Ed25519 publisher key (OpenSSL 3)."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        # OpenSSL diagnostics can contain key paths; expose only the operation.
        raise RuntimeError("Publisher key/signature operation failed")
    return result.stdout


def sign(directory: Path, encoded_key: str, openssl: str = "openssl"):
    manifests = sorted(directory.glob("jlshell-link-agent-java-*.manifest.json"))
    if len(manifests) != 3:
        raise ValueError("Expected exactly three platform manifests")
    with tempfile.TemporaryDirectory(prefix="link-publisher-") as temporary:
        os.chmod(temporary, 0o700)
        key = Path(temporary) / "publisher.der"
        # Create with private permissions before writing any key bytes.
        with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(base64.b64decode(encoded_key, validate=True))
        public = run(openssl, "pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER")
        # RFC 8410 Ed25519 SubjectPublicKeyInfo: prevent use of RSA/EC keys.
        if len(public) != 44 or public[:12] != bytes.fromhex("302a300506032b6570032100"):
            raise ValueError("Publisher key must be Ed25519")
        key_id = hashlib.sha256(public).hexdigest()
        for manifest in manifests:
            signature = run(openssl, "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                            "-inkey", str(key), "-in", str(manifest))
            if len(signature) != 64:
                raise ValueError("Invalid Ed25519 signature length")
            envelope = {"schemaVersion": 1, "algorithm": "Ed25519", "keyId": key_id,
                        "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                        "signature": base64.b64encode(signature).decode("ascii")}
            destination = manifest.with_name(manifest.name.replace(".manifest.json", ".signature.json"))
            destination.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return key_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    value = os.environ.get("JLSHELL_AGENT_PUBLISHER_PRIVATE_KEY", "")
    if not value:
        raise SystemExit("Missing JLSHELL_AGENT_PUBLISHER_PRIVATE_KEY (base64 PKCS8 DER)")
    try:
        identifier = sign(args.directory, value, args.openssl)
    except Exception:
        raise SystemExit("Agent manifest signing failed; check the dedicated Ed25519 publisher key") from None
    print("Signed three Agent manifests; publisher key ID: " + identifier)
