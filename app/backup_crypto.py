"""Optional passphrase encryption for database backups.

Format (all integers big-endian where applicable)::

    magic  8 bytes   b"VSBACKUP"
    version 1 byte   1
    salt   16 bytes  PBKDF2 salt
    nonce  12 bytes  AES-GCM nonce
    ciphertext       AES-256-GCM ciphertext + tag

The passphrase is never stored. Losing it means losing the backup.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"VSBACKUP"
VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
ITERATIONS = 240_000
ENCRYPTED_SUFFIX = ".vsenc"


class BackupCryptoError(ValueError):
    pass


def _key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise BackupCryptoError("A backup passphrase is required")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def is_encrypted(path: str | Path) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(len(MAGIC) + 1) == MAGIC + bytes([VERSION])
    except OSError:
        return False


def encrypt_file(source: str | Path, destination: str | Path, passphrase: str) -> None:
    source_path = Path(source)
    destination_path = Path(destination)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _key(passphrase, salt)
    cipher = AESGCM(key)
    with source_path.open("rb") as reader, destination_path.open("wb") as writer:
        writer.write(MAGIC + bytes([VERSION]) + salt + nonce)
        # AES-GCM is one-shot in the cryptography API. Backups are bounded by
        # the database size; read it in one buffer to keep the format simple
        # and authenticated as a whole.
        plaintext = reader.read()
        writer.write(cipher.encrypt(nonce, plaintext, MAGIC + bytes([VERSION])))
    try:
        os.chmod(destination_path, 0o600)
    except OSError:
        pass


def decrypt_file(source: str | Path, destination: str | Path, passphrase: str) -> None:
    source_path = Path(source)
    with source_path.open("rb") as handle:
        header = handle.read(len(MAGIC) + 1)
        if header != MAGIC + bytes([VERSION]):
            raise BackupCryptoError("Not a VulnScanner encrypted backup")
        salt = handle.read(SALT_BYTES)
        nonce = handle.read(NONCE_BYTES)
        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
            raise BackupCryptoError("Encrypted backup header is truncated")
        ciphertext = handle.read()
    key = _key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, MAGIC + bytes([VERSION])
        )
    except Exception as exc:
        raise BackupCryptoError(
            "Could not decrypt the backup: wrong passphrase or corrupted file"
        ) from exc
    with Path(destination).open("wb") as writer:
        writer.write(plaintext)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
