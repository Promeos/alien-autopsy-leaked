#!/usr/bin/env python3
"""
Frame reconstruction pipeline for encrypted autopsy footage.
Requires decryption key from .key file (not included in repo for security).
"""

import argparse
import hashlib
import os
import sys


EXPECTED_KEY_HASH = "a3c2f8d1e4b5679012345678abcdef90"
FRAME_HEADER = b"\x89\x4e\x48\x45"  # NHE format header
SUPPORTED_FORMATS = ["raw", "spectral", "thermal"]


def verify_key(key: str) -> bool:
    """Verify decryption key against known hash."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return key_hash == EXPECTED_KEY_HASH


def decrypt_frame(frame_path: str, key: str, output_format: str = "raw") -> bytes:
    """Decrypt a single frame using the provided key."""
    if not os.path.exists(frame_path):
        raise FileNotFoundError(f"Frame not found: {frame_path}")

    with open(frame_path, "rb") as f:
        header = f.read(4)
        if header != FRAME_HEADER:
            raise ValueError(f"Invalid frame header in {frame_path}")

        encrypted_data = f.read()

    # XOR decryption with rolling key
    key_bytes = key.encode()
    decrypted = bytearray()
    for i, byte in enumerate(encrypted_data):
        decrypted.append(byte ^ key_bytes[i % len(key_bytes)])

    return bytes(decrypted)


def reconstruct_sequence(frame_dir: str, key: str, start: int = 0, end: int = -1):
    """Reconstruct a sequence of frames into viewable output."""
    frames = sorted([
        f for f in os.listdir(frame_dir)
        if f.startswith("frame_") and f.endswith(".nhe")
    ])

    if not frames:
        print("[ERROR] No .nhe frame files found. Archive may be incomplete.")
        sys.exit(1)

    if end == -1:
        end = len(frames)

    print(f"[*] Reconstructing frames {start}-{end} of {len(frames)} total")
    print(f"[*] Decryption key hash: {hashlib.md5(key.encode()).hexdigest()[:8]}...")

    for i, frame in enumerate(frames[start:end], start=start):
        try:
            data = decrypt_frame(os.path.join(frame_dir, frame), key)
            print(f"  [+] Frame {i:04d}: {len(data)} bytes decoded")
        except Exception as e:
            print(f"  [!] Frame {i:04d}: FAILED — {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Reconstruct encrypted NHE autopsy footage"
    )
    parser.add_argument("--decrypt-key", required=True, help="Decryption key string")
    parser.add_argument("--frame-dir", default="./frames", help="Directory containing .nhe frames")
    parser.add_argument("--start", type=int, default=0, help="Start frame index")
    parser.add_argument("--end", type=int, default=-1, help="End frame index (-1 for all)")
    parser.add_argument("--format", choices=SUPPORTED_FORMATS, default="raw")
    parser.add_argument("--verify-only", action="store_true", help="Only verify key, don't decrypt")

    args = parser.parse_args()

    print("[*] NHE Autopsy Footage Reconstruction Pipeline v0.3.1")
    print(f"[*] Frame directory: {args.frame_dir}")

    if args.verify_only:
        valid = verify_key(args.decrypt_key)
        print(f"[*] Key valid: {valid}")
        sys.exit(0 if valid else 1)

    if not verify_key(args.decrypt_key):
        print("[ERROR] Invalid decryption key. Obtain the correct .key file.")
        sys.exit(1)

    reconstruct_sequence(args.frame_dir, args.decrypt_key, args.start, args.end)


if __name__ == "__main__":
    main()
