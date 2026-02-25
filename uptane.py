"""
Uptane-style OTA update simulation (educational model, not production code).

What Uptane is:
- Uptane is a secure software-update framework for vehicles.
- It is not one fixed packet layout; it is a trust model + verification workflow.
- It extends TUF ideas for automotive ECUs (authenticity, integrity, anti-rollback,
  compromise resilience, and role separation).

Role and trust separation (conceptual mapping in this file):
- OEM blob signer:
  Signs the encrypted update blob/package.
  In this file: `_sign_blob()` / `verify_blob_signature()`.
- Director metadata signer:
  Signs metadata that defines what target is allowed (hash, length, version,
  hardware compatibility, expiry).
  In this file: `_sign_targets_metadata()` / `verify_targets_metadata_signature()`.
- Vehicle ECU (HSM/private key holder):
  Recovers per-update session key from `RecipientInfo`, decrypts payload,
  and verifies decrypted payload against signed metadata.
  In this file: `recover_session_key()`, `decrypt_firmware_payload()`,
  `verify_payload_against_target()`.

End-to-end flow in this model:
1. Verify blob signature and metadata signature/expiry.
2. Select target by hardware + anti-rollback policy.
3. Recover session key from RecipientInfo (ECIES-style ECDH/HKDF/AES-GCM wrapping).
4. Decrypt firmware payload (AES-GCM).
5. Validate decrypted payload hash/length against signed metadata.

Variables you can change (implementation/profile knobs):
- Payload encryption algorithm and key size (example: AES-128-GCM vs AES-256-GCM).
- Session-key wrapping construction (ECIES parameters, KDF, AEAD).
- Signing algorithms/curves (for blob and metadata signatures).
- Metadata policy values (expiry window, version checks, hardware matching strictness).
- Per-deployment trust roots and key lifecycle/rotation strategy.

Note:
- SHA-256 is a hash algorithm, not a key.
- This script keeps deterministic values for reproducible simulation output.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SECP256R1_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)

# ---------------------------------------------------------
# CONFIGURATION KNOBS (SIMULATION PROFILE)
# ---------------------------------------------------------
# These are the main variables to tune when comparing profiles or standards.
# Keep producer/consumer sides aligned if you change any cryptographic primitive.
PAYLOAD_AEAD_ALGORITHM = "aes_256_gcm"
KEY_WRAP_ALGORITHM = "ecies_nist_p256_hkdf_sha256_aes_256_gcm"
BLOB_SIGNATURE_CURVE = "nist_p256"
METADATA_SIGNATURE_SCHEME = "ecdsa_sha256_nist_p256"
PAYLOAD_HASH_ALGORITHM = "sha256"

DIRECTOR_SIGNING_KEY_LABEL = "director-metadata-signing-key"
BLOB_SIGNING_KEY_LABEL = "oem-root-ca-signing-key"
RECIPIENT_PRIVATE_KEY_LABEL = "vin-5566-ecu-private-key"


def _hex(data: bytes) -> str:
    return f"0x{data.hex()}"


def _unhex(value: str) -> bytes:
    normalized = value[2:] if value.startswith("0x") else value
    return bytes.fromhex(normalized)


def _deterministic_bytes(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _derive_private_key(label: str) -> ec.EllipticCurvePrivateKey:
    seed = hashlib.sha256(label.encode("utf-8")).digest()
    private_value = (int.from_bytes(seed, "big") % (SECP256R1_ORDER - 1)) + 1
    return ec.derive_private_key(private_value, ec.SECP256R1())


def _parse_utc_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def _recipient_private_key() -> ec.EllipticCurvePrivateKey:
    return _derive_private_key(RECIPIENT_PRIVATE_KEY_LABEL)


# ---------------------------------------------------------
# FILE 0: THE PLAINTEXT FIRMWARE IMAGE
# ---------------------------------------------------------


@dataclass(frozen=True)
class UpdateFirmware:
    filename: str
    version: int
    hardware_ids: List[str]
    release_notes: str
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def to_dict(self) -> Dict[str, object]:
        preview = _hex(self.payload[:64])
        if self.length > 64:
            preview = f"{preview}..."

        return {
            "filename": self.filename,
            "version": self.version,
            "hardware_ids": self.hardware_ids,
            "release_notes": self.release_notes,
            "length": self.length,
            "sha256": self.sha256,
            "payload_preview": preview,
        }


def default_update_firmware() -> UpdateFirmware:
    manifest = (
        "target=ECU_Type_A\n"
        "version=2\n"
        "secure_boot=true\n"
        "anti_rollback=true\n"
        "module=v2x_comms\n"
    ).encode("utf-8")

    package_header = b"V2XFWPKG" + (2).to_bytes(2, "big") + len(manifest).to_bytes(2, "big")
    sections = (
        _deterministic_bytes(b"uptane-demo-kernel", 4096)
        + _deterministic_bytes(b"uptane-demo-v2x-stack", 4096)
        + _deterministic_bytes(b"uptane-demo-calibration", 2048)
    )
    payload = package_header + manifest + sections

    return UpdateFirmware(
        filename="firmware_v2.0.bin",
        version=2,
        hardware_ids=["ECU_Type_A"],
        release_notes="Adds anti-rollback checks and hardened V2X crypto settings.",
        payload=payload,
    )


# ---------------------------------------------------------
# FILE 1: THE UPDATE BLOB (THE "PACKAGE")
# ---------------------------------------------------------


@dataclass(frozen=True)
class Header:
    protocol_version: int = 3
    type: str = "encrypted_data"
    generated_at: str = "2026-02-06T10:00:00Z"


@dataclass(frozen=True)
class RecipientInfo:
    recipient_id: str
    key_encryption_algorithm: str
    ephemeral_public_key: str
    key_wrap_nonce: str
    encrypted_session_key: str


@dataclass(frozen=True)
class Ciphertext:
    symmetric_algorithm: str
    nonce: str
    payload: str
    authentication_tag: str


@dataclass(frozen=True)
class Signature:
    curve: str
    signer_id: str
    r_value: str
    s_value: str


@dataclass(frozen=True)
class UpdateBlob:
    header: Header
    recipients: List[RecipientInfo]
    ciphertext: Ciphertext
    signature: Signature

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _encrypt_firmware_payload(firmware: UpdateFirmware) -> Tuple[Ciphertext, bytes]:
    session_key = hashlib.sha256(b"uptane-demo-session-key-v1").digest()
    nonce = hashlib.sha256(b"uptane-demo-payload-nonce-v1").digest()[:12]
    aad = f"{firmware.filename}:{firmware.version}:{','.join(firmware.hardware_ids)}".encode(
        "utf-8"
    )

    encrypted_payload = AESGCM(session_key).encrypt(nonce, firmware.payload, aad)
    encrypted_body = encrypted_payload[:-16]
    auth_tag = encrypted_payload[-16:]

    return (
        Ciphertext(
            symmetric_algorithm=PAYLOAD_AEAD_ALGORITHM,
            nonce=_hex(nonce),
            payload=_hex(encrypted_body),
            authentication_tag=_hex(auth_tag),
        ),
        session_key,
    )


def _build_recipient_info(session_key: bytes) -> RecipientInfo:
    recipient_private_key = _recipient_private_key()
    recipient_public_key = recipient_private_key.public_key()
    ephemeral_private_key = _derive_private_key("oem-director-ephemeral-wrap-key")

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    key_encryption_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"uptane-demo-ecies-salt",
        info=b"session-key-wrap",
    ).derive(shared_secret)

    wrap_nonce = hashlib.sha256(b"uptane-demo-wrap-nonce-v1").digest()[:12]
    encrypted_session_key = AESGCM(key_encryption_key).encrypt(
        wrap_nonce, session_key, b"VIN_5566_HASH"
    )
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )

    return RecipientInfo(
        recipient_id="VIN_5566_HASH",
        key_encryption_algorithm=KEY_WRAP_ALGORITHM,
        ephemeral_public_key=_hex(ephemeral_public_key),
        key_wrap_nonce=_hex(wrap_nonce),
        encrypted_session_key=_hex(encrypted_session_key),
    )


def _blob_payload_for_signature(
    header: Header, recipients: List[RecipientInfo], ciphertext: Ciphertext
) -> bytes:
    payload = {
        "header": asdict(header),
        "recipients": [asdict(recipient) for recipient in recipients],
        "ciphertext": asdict(ciphertext),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_blob(header: Header, recipients: List[RecipientInfo], ciphertext: Ciphertext) -> Signature:
    signer_private_key = _derive_private_key(BLOB_SIGNING_KEY_LABEL)
    payload = _blob_payload_for_signature(header, recipients, ciphertext)
    der_signature = signer_private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = utils.decode_dss_signature(der_signature)

    return Signature(
        curve=BLOB_SIGNATURE_CURVE,
        signer_id="OEM_Root_CA_ID",
        r_value=f"0x{r_value:064x}",
        s_value=f"0x{s_value:064x}",
    )


def default_update_blob(firmware: UpdateFirmware) -> UpdateBlob:
    header = Header()
    ciphertext, session_key = _encrypt_firmware_payload(firmware)
    recipients = [_build_recipient_info(session_key)]
    signature = _sign_blob(header, recipients, ciphertext)

    return UpdateBlob(
        header=header,
        recipients=recipients,
        ciphertext=ciphertext,
        signature=signature,
    )


def verify_blob_signature(blob: UpdateBlob) -> bool:
    verifier_key = _derive_private_key(BLOB_SIGNING_KEY_LABEL).public_key()
    payload = _blob_payload_for_signature(blob.header, blob.recipients, blob.ciphertext)
    der_signature = utils.encode_dss_signature(
        int(blob.signature.r_value, 16),
        int(blob.signature.s_value, 16),
    )

    try:
        verifier_key.verify(der_signature, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def find_recipient_info(blob: UpdateBlob, recipient_id: str) -> RecipientInfo:
    for recipient in blob.recipients:
        if recipient.recipient_id == recipient_id:
            return recipient
    raise ValueError(f"No recipient information for {recipient_id}")


def recover_session_key(
    recipient: RecipientInfo, recipient_private_key: ec.EllipticCurvePrivateKey
) -> bytes:
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        _unhex(recipient.ephemeral_public_key),
    )
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    key_encryption_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"uptane-demo-ecies-salt",
        info=b"session-key-wrap",
    ).derive(shared_secret)

    return AESGCM(key_encryption_key).decrypt(
        _unhex(recipient.key_wrap_nonce),
        _unhex(recipient.encrypted_session_key),
        recipient.recipient_id.encode("utf-8"),
    )


# ---------------------------------------------------------
# FILE 2: THE UPTANE METADATA (THE "MENU")
# ---------------------------------------------------------


@dataclass(frozen=True)
class Hashes:
    sha256: str


@dataclass(frozen=True)
class TargetFile:
    length: int
    hashes: Hashes
    hardware_ids: List[str]
    version: int


@dataclass(frozen=True)
class SignedTargets:
    expires: str
    targets: Dict[str, TargetFile]


@dataclass(frozen=True)
class SignatureEntry:
    keyid: str
    sig: str


@dataclass(frozen=True)
class TargetsMetadata:
    signed: SignedTargets
    signatures: List[SignatureEntry]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class VehicleContext:
    recipient_id: str
    hardware_id: str
    current_version: int


def _targets_payload_for_signature(signed_targets: SignedTargets) -> bytes:
    return json.dumps(asdict(signed_targets), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _sign_targets_metadata(signed_targets: SignedTargets) -> SignatureEntry:
    director_key = _derive_private_key(DIRECTOR_SIGNING_KEY_LABEL)
    signature = director_key.sign(_targets_payload_for_signature(signed_targets), ec.ECDSA(hashes.SHA256()))
    return SignatureEntry(keyid="Director_Key_ID", sig=_hex(signature))


def verify_targets_metadata_signature(metadata: TargetsMetadata) -> bool:
    verifier_key = _derive_private_key(DIRECTOR_SIGNING_KEY_LABEL).public_key()
    payload = _targets_payload_for_signature(metadata.signed)

    for signature_entry in metadata.signatures:
        if signature_entry.keyid != "Director_Key_ID":
            continue
        try:
            verifier_key.verify(_unhex(signature_entry.sig), payload, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


def verify_targets_metadata_fresh(metadata: TargetsMetadata, now_utc: datetime) -> bool:
    return _parse_utc_timestamp(metadata.signed.expires) > now_utc


def select_target_for_vehicle(
    metadata: TargetsMetadata, vehicle: VehicleContext
) -> Tuple[str, TargetFile]:
    for filename, target in metadata.signed.targets.items():
        if vehicle.hardware_id not in target.hardware_ids:
            continue
        if target.version <= vehicle.current_version:
            continue
        return filename, target
    raise ValueError("No compatible target for this vehicle (hardware/version policy)")


def decrypt_firmware_payload(
    blob: UpdateBlob, session_key: bytes, target_filename: str, target: TargetFile
) -> bytes:
    aad = f"{target_filename}:{target.version}:{','.join(target.hardware_ids)}".encode("utf-8")
    encrypted_payload = _unhex(blob.ciphertext.payload) + _unhex(blob.ciphertext.authentication_tag)
    return AESGCM(session_key).decrypt(_unhex(blob.ciphertext.nonce), encrypted_payload, aad)


def verify_payload_against_target(payload: bytes, target: TargetFile) -> bool:
    return (
        len(payload) == target.length
        and hashlib.sha256(payload).hexdigest() == target.hashes.sha256
    )


def default_targets_metadata(firmware: UpdateFirmware) -> TargetsMetadata:
    signed_targets = SignedTargets(
        expires="2027-01-01T00:00:00Z",
        targets={
            firmware.filename: TargetFile(
                length=firmware.length,
                hashes=Hashes(sha256=firmware.sha256),
                hardware_ids=firmware.hardware_ids,
                version=firmware.version,
            )
        },
    )

    return TargetsMetadata(
        signed=signed_targets,
        signatures=[_sign_targets_metadata(signed_targets)],
    )


DEFAULT_UPDATE_FIRMWARE = default_update_firmware()
DEFAULT_UPDATE_BLOB = default_update_blob(DEFAULT_UPDATE_FIRMWARE)
DEFAULT_TARGETS_METADATA = default_targets_metadata(DEFAULT_UPDATE_FIRMWARE)
DEFAULT_VEHICLE_CONTEXT = VehicleContext(
    recipient_id="VIN_5566_HASH",
    hardware_id="ECU_Type_A",
    current_version=1,
)


def main() -> None:
    print("=" * 50)
    print("SIMULATION OF UPTANE UPDATE PROCESS")
    print("=" * 50 + "\n")

    print("Step 0: Building plaintext firmware...")
    print(f"Firmware: {DEFAULT_UPDATE_FIRMWARE.filename} v{DEFAULT_UPDATE_FIRMWARE.version}")
    print(f"Size: {DEFAULT_UPDATE_FIRMWARE.length} bytes")
    print(f"SHA-256: {DEFAULT_UPDATE_FIRMWARE.sha256}\n")

    print("Step 1: Signature and metadata checks...")
    blob_signature_valid = verify_blob_signature(DEFAULT_UPDATE_BLOB)
    metadata_signature_valid = verify_targets_metadata_signature(DEFAULT_TARGETS_METADATA)
    metadata_fresh = verify_targets_metadata_fresh(
        DEFAULT_TARGETS_METADATA,
        datetime(2026, 2, 6, 10, 0, 0, tzinfo=timezone.utc),
    )
    print(f"Blob signature valid: {blob_signature_valid}")
    print(f"Targets metadata signature valid: {metadata_signature_valid}")
    print(f"Targets metadata not expired: {metadata_fresh}")
    if not (blob_signature_valid and metadata_signature_valid and metadata_fresh):
        print("Update rejected before decryption.")
        return
    print("")

    print("Step 2: RecipientInfo -> session key...")
    try:
        target_filename, target = select_target_for_vehicle(
            DEFAULT_TARGETS_METADATA,
            DEFAULT_VEHICLE_CONTEXT,
        )
        recipient_info = find_recipient_info(
            DEFAULT_UPDATE_BLOB,
            DEFAULT_VEHICLE_CONTEXT.recipient_id,
        )
        session_key = recover_session_key(recipient_info, _recipient_private_key())
    except ValueError as error:
        print(f"Update rejected: {error}")
        return
    print(f"Selected target: {target_filename} (v{target.version})")
    print(f"Recovered session key bytes: {len(session_key)}\n")

    print("Step 3: Decrypt payload with session key...")
    try:
        decrypted_payload = decrypt_firmware_payload(
            DEFAULT_UPDATE_BLOB,
            session_key,
            target_filename,
            target,
        )
    except Exception as error:
        print(f"Decryption failed: {error}")
        return
    print(f"Decrypted payload bytes: {len(decrypted_payload)}")
    print(f"Payload equals original firmware: {decrypted_payload == DEFAULT_UPDATE_FIRMWARE.payload}\n")

    print("Step 4: Check decrypted payload against Uptane metadata...")
    hash_matches = hashlib.sha256(decrypted_payload).hexdigest() == target.hashes.sha256
    length_matches = len(decrypted_payload) == target.length
    metadata_match = verify_payload_against_target(decrypted_payload, target)
    print(f"SHA-256 matches metadata: {hash_matches}")
    print(f"Length matches metadata: {length_matches}")
    print(f"Overall metadata check: {metadata_match}")
    print(f"Install decision: {'ACCEPTED' if metadata_match else 'REJECTED'}")


if __name__ == "__main__":
    main()
