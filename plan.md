# Uptane Cryptographic Case Study — Java Project Plan

## Goal

Port the `uptane.py` simulation to Java with a **modular cryptographic layer** so we can
swap algorithms (e.g. ECDSA P-256 vs Ed25519 vs RSA-2048/3072, AES-128-GCM vs AES-256-GCM vs ChaCha20-Poly1305)
and **measure**:

| Metric | What it tells us |
|---|---|
| Signed / encrypted byte count | Size overhead per algorithm |
| Signature generation time (ns) | Cost on OEM / Director side |
| Signature verification time (ns) | Cost on ECU (vehicle) side |
| Encryption time (ns) | Payload protection cost |
| Decryption time (ns) | ECU install cost |
| Key generation time (ns) | Provisioning cost |

Results are printed as a comparison table at the end of the run, making them easy to
paste into the case-study paper.

---

## Architecture (packages & classes)

The project is organized around the **three Uptane roles**: OEM (Image repository),
Director, and Vehicle (Primary ECU). Each role is its own package with clear
responsibilities, mirroring how trust and data flow in the real framework.

```
src/main/java/uptane/
├── crypto/                        # ← the swappable layer (algorithm-agnostic)
│   ├── CryptoProfile.java             # record: bundles a Signer + Encryptor + KeyWrapper + Hasher
│   ├── Signer.java                     # interface: generateKeyPair / sign / verify
│   ├── Encryptor.java                  # interface: encrypt / decrypt (AEAD)
│   ├── KeyWrapper.java                 # interface: wrapSessionKey / unwrapSessionKey
│   ├── Hasher.java                     # interface: hash
│   ├── EcdsaP256Signer.java            # impl
│   ├── Ed25519Signer.java              # impl (BouncyCastle)
│   ├── RsaSigner.java                  # impl (RSA-2048 / RSA-3072 PSS)
│   ├── AesGcmEncryptor.java            # impl (AES-128-GCM / AES-256-GCM)
│   ├── ChaCha20Encryptor.java          # impl (ChaCha20-Poly1305)
│   ├── EciesKeyWrapper.java            # impl (ECDH + HKDF + AEAD wrap)
│   ├── RsaKeyWrapper.java              # impl (RSA-OAEP wrap)
│   └── Sha2Hasher.java                 # impl (SHA-256 / SHA-384 / SHA-512)
│
├── model/                         # ← shared data structures (Java records)
│   ├── UpdateFirmware.java             # plaintext firmware image
│   ├── UpdateBlob.java                 # the encrypted package (header + recipients + ciphertext + sig)
│   ├── RecipientInfo.java              # per-ECU wrapped session key
│   ├── Ciphertext.java                 # encrypted payload + nonce + tag
│   ├── SignatureEntry.java             # signature value (r,s or raw bytes + signer id)
│   ├── TargetsMetadata.java            # signed targets (hash, length, version, hw-id)
│   ├── TargetFile.java                 # single target descriptor
│   └── VehicleContext.java             # vehicle identity (VIN, hardware-id, current version)
│
├── oem/                           # ← OEM role (Image repository)
│   └── OemPackager.java                # builds firmware, encrypts payload, signs the blob
│                                       #   - generates session key
│                                       #   - encrypts firmware with Encryptor
│                                       #   - wraps session key per recipient with KeyWrapper
│                                       #   - signs the complete blob with Signer (OEM key)
│                                       #   - returns UpdateBlob
│
├── director/                      # ← Director role
│   └── DirectorService.java            # builds & signs targets metadata
│                                       #   - hashes firmware with Hasher
│                                       #   - constructs TargetsMetadata (hash, length, version, expiry, hw-ids)
│                                       #   - signs metadata with Signer (Director key)
│                                       #   - returns TargetsMetadata
│
├── vehicle/                       # ← Vehicle / Primary ECU role
│   └── VehicleEcu.java                 # verifies everything, decrypts, installs
│                                       #   - verifies blob signature (OEM public key)
│                                       #   - verifies metadata signature (Director public key)
│                                       #   - checks metadata freshness + anti-rollback
│                                       #   - selects target by hardware-id
│                                       #   - unwraps session key with KeyWrapper (ECU private key)
│                                       #   - decrypts payload with Encryptor
│                                       #   - validates hash + length against metadata
│                                       #   - returns install decision
│
├── benchmark/                     # ← measurement harness
│   ├── BenchmarkRunner.java            # runs the full OEM→Director→Vehicle flow per profile
│   ├── BenchmarkResult.java            # record: profile name → Map<metric, value>
│   └── ResultPrinter.java              # prints comparison table (console + CSV)
│
└── Main.java                      # entry point — runs all profiles, prints table
```

### Data flow between roles

```
                      ┌─────────────────┐
                      │   UpdateFirmware │  (plaintext image)
                      └────────┬────────┘
                               │
               ┌───────────────┼───────────────┐
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │  OemPackager   │               │DirectorService│
       │  (oem/)        │               │  (director/)  │
       │                │               │               │
       │ encrypt payload│               │ hash firmware │
       │ wrap session key│              │ build targets │
       │ sign blob      │               │ sign metadata │
       └───────┬────────┘               └───────┬───────┘
               │                                │
               │  UpdateBlob                    │  TargetsMetadata
               │                                │
               └───────────────┬────────────────┘
                               ▼
                       ┌───────────────┐
                       │  VehicleEcu   │
                       │  (vehicle/)   │
                       │               │
                       │ verify sigs   │
                       │ check metadata│
                       │ unwrap key    │
                       │ decrypt       │
                       │ validate hash │
                       │ → ACCEPT/REJECT│
                       └───────────────┘
```

---

## Crypto profiles to compare

| Profile name | Signing | Payload AEAD | Key wrap | Hash |
|---|---|---|---|---|
| `BASELINE_P256` | ECDSA P-256 | AES-256-GCM | ECIES P-256 | SHA-256 |
| `ED25519_AES256` | Ed25519 | AES-256-GCM | X25519+HKDF | SHA-256 |
| `RSA2048_AES128` | RSA-2048 PSS | AES-128-GCM | RSA-OAEP | SHA-256 |
| `RSA3072_AES256` | RSA-3072 PSS | AES-256-GCM | RSA-OAEP | SHA-256 |
| `P256_CHACHA` | ECDSA P-256 | ChaCha20-Poly1305 | ECIES P-256 | SHA-256 |

> These five cover the most relevant trade-offs for the paper:
> ECC vs RSA, key-size impact, AEAD choice, and the Uptane-recommended baseline.

---

## Build tool

**Maven** with a single module.

Dependencies:
- `org.bouncycastle:bcprov-jdk18on` — needed for Ed25519, X25519, and some
  older-JDK fallbacks.
- No other external deps. JDK 17+ standard crypto covers the rest.

---

## Step-by-step implementation order

### Step 1 — Project skeleton
- `pom.xml` with BouncyCastle dependency, JDK 17 compiler settings.
- Package directories as shown above.
- `Main.java` with an empty `main()`.

### Step 2 — Model classes
- Translate the Python `@dataclass` types into Java records (JDK 16+).
- `UpdateFirmware`, `UpdateBlob`, `RecipientInfo`, `Ciphertext`, `SignatureEntry`,
  `TargetsMetadata`, `TargetFile`, `VehicleContext`.
- Include the deterministic-bytes helper and hex utilities.

### Step 3 — Crypto interfaces + baseline implementation
- Define `Signer`, `Encryptor`, `KeyWrapper`, `Hasher` interfaces.
- Implement `EcdsaP256Signer`, `AesGcmEncryptor`, `EciesKeyWrapper`, `Sha2Hasher`.
- Bundle them into `CryptoProfile.BASELINE_P256`.

### Step 4 — OEM role (`OemPackager`)
- Takes `UpdateFirmware` + `CryptoProfile` → produces `UpdateBlob`.
- Generates session key, encrypts payload (`Encryptor`).
- Wraps session key for each recipient (`KeyWrapper`).
- Signs the complete blob (`Signer` with OEM key).

### Step 5 — Director role (`DirectorService`)
- Takes `UpdateFirmware` + `CryptoProfile` → produces `TargetsMetadata`.
- Hashes firmware (`Hasher`), builds target descriptor.
- Signs targets metadata (`Signer` with Director key).

### Step 6 — Vehicle role (`VehicleEcu`)
- Takes `UpdateBlob` + `TargetsMetadata` + `VehicleContext` + `CryptoProfile`.
- Verifies blob signature (OEM public key).
- Verifies metadata signature (Director public key).
- Checks freshness + anti-rollback + hardware-id match.
- Unwraps session key (`KeyWrapper` with ECU private key).
- Decrypts payload (`Encryptor`).
- Validates hash + length against signed metadata (`Hasher`).
- Returns install decision (ACCEPTED / REJECTED).

### Step 7 — End-to-end smoke test
- Run the full OEM → Director → Vehicle flow with `BASELINE_P256`.
- Assert the decrypted payload matches the original firmware.

### Step 8 — Additional crypto implementations
- `Ed25519Signer` + X25519 key wrapper (BouncyCastle).
- `RsaSigner` (RSA-2048 PSS, RSA-3072 PSS) + `RsaKeyWrapper` (RSA-OAEP).
- `ChaCha20Encryptor`.
- Register profiles `ED25519_AES256`, `RSA2048_AES128`, `RSA3072_AES256`, `P256_CHACHA`.

### Step 9 — Benchmark harness
- `BenchmarkRunner`: for each profile, run the full OEM → Director → Vehicle
  flow N times (configurable, default 100), record `System.nanoTime()` deltas
  for each phase **per role**:
  - OEM: key-gen, encrypt, key-wrap, sign
  - Director: hash, sign
  - Vehicle: verify (×2), unwrap, decrypt, hash-check
- Collect byte counts: signature size, ciphertext size, metadata size.
- `ResultPrinter`: output a Markdown table + CSV to stdout.

### Step 10 — Final polish
- Make sure `Main.java` runs all profiles and prints the comparison table.
- Verify results are reproducible (deterministic keys, same firmware payload).

---

## What we intentionally skip

- TLS / network transport (not relevant to the crypto comparison).
- Full TUF role hierarchy (Root, Timestamp, Snapshot) — we focus on Targets
  signing and payload encryption, which is where the algorithm choice matters.
- HSM integration — out of scope for an academic case study.
- Multi-ECU / multi-vehicle fanout — one vehicle context is enough to measure.

---

## Expected output (example)

```
================================================================
  UPTANE CRYPTOGRAPHIC PROFILE COMPARISON
================================================================

Profile           | Sign (µs) | Verify (µs) | Encrypt (µs) | Decrypt (µs) | Sig bytes | CT bytes
------------------+-----------+-------------+--------------+--------------+-----------+---------
BASELINE_P256     |       142 |         187 |           58 |           53 |        64 |   10284
ED25519_AES256    |        38 |          72 |           57 |           52 |        64 |   10284
RSA2048_AES128    |      1842 |          42 |           55 |           51 |       256 |   10268
RSA3072_AES256    |      5210 |          58 |           58 |           53 |       384 |   10284
P256_CHACHA       |       143 |         188 |           51 |           48 |        64 |   10284

(100 iterations, median values, JDK 17, Intel i7-12700H)
```

This table is the core deliverable for the case-study paper.
