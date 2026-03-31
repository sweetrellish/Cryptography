# Cryptography

Course workspace for cryptography-focused simulations and labs.

## Main Project

The primary code lives in `VPN Project/`.

- Start here for setup and usage: `VPN Project/README.md`
- Full implementation timeline and command history: `VPN Project/PROJECT_REFERENCE.md`

## AES Class Focus

Within `VPN Project/`, the AES simulator now includes two paths:

- Standard engine: AES-CBC and AES-GCM via the cryptography library
- Rijndael Process engine: process-focused AES-128 CBC with optional round/block trace output

Run from `VPN Project/`:

```bash
python AESSimulator.py
```
