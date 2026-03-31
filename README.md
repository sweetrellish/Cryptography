# Cryptography — Educational VPN + AES Mode Lab

## Overview
This repo is a hands-on learning environment centered on **secure communication concepts**—built around a **Python + Tkinter GUI “VPN simulator”** and a companion **AES classroom simulator** that makes encryption mode behavior easy to see, test, and demo.

This is explicitly positioned as a **simulation/teaching project**, not production VPN software.

---

## What’s Inside

### 1) VPN Simulator (COSC 370)
**`VPN Project/VPNSimulator.py`**

A Tkinter-based VPN transfer simulation that:
- Packages user input into a **JSON “packet”**
- Encrypts the packet using **AES (CBC or GCM selectable)**
- Shows the “tunnel” view (IV + ciphertext) and server-side decrypted output
- Adds realism with **simulated latency** and **packet loss**
- Includes a **Diffie–Hellman + HKDF** key derivation flow plus optional HMAC in CBC mode

**Concepts demonstrated:** packet encapsulation, confidentiality vs integrity, IVs/nonces, key exchange, and what “encrypted traffic” looks like in transit.

### 2) AES Encryption Simulator (MATH 447 Starter)
**`VPN Project/AESSimulator.py`** + **`VPN Project/aes_core.py`**

A standalone GUI for AES experimentation:
- Supports **AES-CBC (PKCS7 padding)** and **AES-GCM (AEAD w/ tag + optional AAD)**
- Generates keys + IV/nonce, encrypts plaintext into a **JSON packet**, and decrypts back
- Includes a **Mode Comparison Lab** to visualize pattern leakage:
  - ECB vs CBC vs GCM repeated-block analysis

**Why it’s clean:** crypto logic is extracted into `aes_core.py`, making it reusable and testable.

### 3) Tests + Reproducibility
**`VPN Project/tests/test_aes_core.py`**
- Verifies CBC round-trip correctness
- Verifies GCM round-trip + AAD
- Confirms tampering causes **GCM tag verification failure**
- Confirms ECB reveals repeated-block structure more than CBC/GCM

---

## Repo Layout (High-Level)
- `VPN Project/README.md`: main usage guide + troubleshooting
- `VPN Project/VPNSimulator.py`: VPN simulator GUI demo
- `VPN Project/AESSimulator.py`: AES simulator GUI demo
- `VPN Project/aes_core.py`: reusable AES helpers + mode comparison utilities
- `VPN Project/tests/test_aes_core.py`: unit tests
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
