# Security-for-embedded-systems

Cryptographic case study of the [Uptane framework](https://uptane.org/) for secure automotive OTA updates.
Compares five crypto profiles (ECDSA P-256, Ed25519, RSA-2048, RSA-3072, ChaCha20-Poly1305) across the three Uptane roles (OEM, Director, Vehicle ECU) and measures signing, encryption, and key-wrapping performance.

## Prerequisites

| Requirement | Version |
|---|---|
| Java (JDK) | 17 or newer |
| Apache Maven | 3.8 or newer |

### Installing on macOS

```bash
brew install openjdk@17 maven
```

### Installing on Windows

1. Download and install [Eclipse Temurin JDK 17+](https://adoptium.net/)
2. Download [Apache Maven](https://maven.apache.org/download.cgi) and add the `bin/` folder to your `PATH`
3. Verify both are available:

```powershell
java -version
mvn -version
```

### Installing on Linux (Debian/Ubuntu)

```bash
sudo apt-get install openjdk-17-jdk maven
```

## Build and run

All commands should be run from the `uptane-crypto-bench/` directory:

```bash
cd uptane-crypto-bench
```

### Compile

```bash
mvn compile
```

### Run (smoke test + benchmark)

**macOS / Linux (Bash):**
```bash
mvn -q exec:java
```

**Windows (PowerShell):**
```powershell
mvn -q exec:java
```

To change the number of benchmark iterations (default 100):

**macOS / Linux:**
```bash
mvn -q exec:java -Dexec.args=50
```

**Windows (PowerShell)** — quote the `-D` argument:
```powershell
mvn -q exec:java "-Dexec.args=50"
```

### Package into a JAR

```bash
mvn package
java -cp "target/uptane-crypto-bench-1.0-SNAPSHOT.jar;target/lib/*" uptane.Main
```

On macOS/Linux use `:` instead of `;` as the classpath separator:
```bash
java -cp "target/uptane-crypto-bench-1.0-SNAPSHOT.jar:target/lib/*" uptane.Main
```

### Clean build artifacts

```bash
mvn clean
```

## Project structure

```
uptane-crypto-bench/
├── pom.xml
└── src/main/java/uptane/
    ├── Main.java                  # Entry point
    ├── crypto/                    # Swappable crypto layer (interfaces + implementations)
    ├── model/                     # Data structures (Java records)
    ├── oem/OemPackager.java       # OEM role: encrypt firmware, wrap session key, sign blob
    ├── director/DirectorService.java  # Director role: hash firmware, sign targets metadata
    ├── vehicle/VehicleEcu.java    # Vehicle role: verify, decrypt, validate
    └── benchmark/                 # Timing harness and result printer
```

## Crypto profiles

| Profile | Signing | Payload AEAD | Key Wrap | Hash |
|---|---|---|---|---|
| BASELINE_P256 | ECDSA P-256 | AES-256-GCM | ECIES P-256 | SHA-256 |
| ED25519_AES256 | Ed25519 | AES-256-GCM | ECIES P-256 | SHA-256 |
| RSA2048_AES128 | RSA-2048 PSS | AES-128-GCM | RSA-OAEP | SHA-256 |
| RSA3072_AES256 | RSA-3072 PSS | AES-256-GCM | RSA-OAEP | SHA-256 |
| P256_CHACHA | ECDSA P-256 | ChaCha20-Poly1305 | ECIES P-256 | SHA-256 |
