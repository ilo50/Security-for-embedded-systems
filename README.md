# Security-for-embedded-systems

Cryptographic case study of the [Uptane framework](https://uptane.org/) for secure automotive OTA updates.
This project simulates an Uptane-style OTA update process using a Python architecture. It benchmarks different cryptographic algorithms for identity signing and payload encryption across the three Uptane roles (Image Repository, Director, and Vehicle ECU).

## Prerequisites
- Python 3.8+
- The `cryptography` Python library.

Install dependencies using:
```bash
pip install -r requirements.txt
```

## Build and run

To run the simulation and benchmark:
```bash
python src/main.py
```

## Project structure

```
.
├── src/
│   ├── main.py              # Entry point for the benchmark simulation
│   ├── crypto_algorithms.py # Swappable crypto layer and benchmarking timer
│   ├── director_repo.py     # Director role (signs metadata)
│   ├── image_repo.py        # OEM / Image Repo role (encrypts payload, signs blob)
│   └── vehicle_ecu.py       # Vehicle ECU role (verifies signatures, decrypts)
├── requirements.txt         # Python dependencies
├── design.png               # Project design architecture diagram
└── Flow_chart.txt           # Process flow description
```

## Crypto profiles

The benchmark currently compares various cryptographic algorithms, for example:
- **Ed25519** (Signing) + **AES-GCM** (Payload AEAD) + **SHA-256** (Hashing)
- **RSA-2048** (Signing) + **ChaCha20-Poly1305** (Payload AEAD) + **SHA-256** (Hashing)

Results are printed to the console showing iteration times, payload sizes, and average latencies for identity operations vs. payload processing.
