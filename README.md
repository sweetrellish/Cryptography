# Cryptography - Educational VPN + AES Mode Lab

## Overview

This repo is a hands-on learning environment centered on secure communication concepts, built around a Python + Tkinter GUI VPN simulator and a companion AES classroom simulator.

This project is intentionally a simulation/teaching environment, not production VPN software.

---

## What's Inside

### 1) VPN Simulator (COSC 370)

`VPN Project/VPNSimulator.py`

A Tkinter-based VPN transfer simulation that:

- Packages user input into a JSON packet
- Encrypts the packet using AES (CBC or GCM selectable)
- Shows tunnel view (IV + ciphertext) and server-side decrypted output
- Adds realism with simulated latency and packet loss
- Includes Diffie-Hellman + HKDF key derivation flow plus optional HMAC in CBC mode

Concepts demonstrated: packet encapsulation, confidentiality vs integrity, IVs/nonces, key exchange, and encrypted traffic representation in transit.

### 2) AES Encryption Simulator (MATH 447 Starter)

`VPN Project/AESSimulator.py` with `VPN Project/aes_core.py` and `VPN Project/aes_core_process.py`

A standalone GUI for AES experimentation:

- Standard engine supports AES-CBC (PKCS7 padding) and AES-GCM (AEAD with tag + optional AAD)
- Rijndael Process engine provides process-focused AES-128 CBC with optional round/block trace output
- Generates keys + IV/nonce, encrypts plaintext into a JSON packet, and decrypts back
- Includes a Mode Comparison Lab to visualize pattern leakage (ECB vs CBC vs GCM repeated-block analysis)

Why it's clean: crypto logic is extracted into reusable modules (`aes_core.py` and `aes_core_process.py`) to keep GUI code simple and testable.

### 3) Tests + Reproducibility

`VPN Project/tests/test_aes_core.py` and `VPN Project/tests/test_aes_core_process.py`

- Verifies CBC and GCM round-trip correctness in the standard path
- Verifies GCM integrity checks fail on tampering
- Verifies ECB pattern leakage comparison behavior
- Verifies AES-128 known-answer behavior and trace flow for the process-focused path

---

## Repo Layout (High-Level)

- `VPN Project/README.md`: main usage guide + troubleshooting
- `VPN Project/PROJECT_REFERENCE.md`: implementation timeline and command log
- `VPN Project/VPNSimulator.py`: VPN simulator GUI demo
- `VPN Project/AESSimulator.py`: AES simulator GUI demo
- `VPN Project/aes_core.py`: reusable AES helpers + mode comparison utilities
- `VPN Project/aes_core_process.py`: explicit AES-128 Rijndael process implementation for teaching
- `VPN Project/tests/test_aes_core.py`: standard AES unit tests
- `VPN Project/tests/test_aes_core_process.py`: process-focused AES unit tests
- `VPN Project/requirements.txt`: pinned dependencies

---

## Quick Start

From `VPN Project/`:

```bash
# 1) Create/activate a venv (Python 3.13 recommended for Tkinter compatibility)
/opt/homebrew/bin/python3.13 -m venv myenv
source myenv/bin/activate

# 2) Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 3) Run either app
python VPNSimulator.py
# or
python AESSimulator.py
```
