# AES Demo Slide Bundle

Generated: 2026-05-14T07:23:01
Engine: Rijndael Process
Mode: CBC
Key Size (selected): 128 bits
Process Trace Enabled: True

## Suggested Slide Flow
1. Show the plaintext and selected AES engine/mode.
2. Explain the generated key and IV/nonce values.
3. Walk through the encrypted packet JSON and identify ciphertext, IV, and metadata.
4. Show the decrypted output to confirm round-trip correctness.
5. If present, use the comparison output or trace data to explain security/process behavior.

## Current Demo Snapshot
- Plaintext length: 0 characters
- Packet JSON present: no
- Decrypted output present: no
- Pattern demo present: no
- Trace entries exported: 0

## Presentation Tips
- Use plaintext.txt and decrypted_output.txt on before/after slides.
- Use packet.json for a zoomed-in ciphertext/IV metadata slide.
- Use comparison.txt for ECB vs CBC vs GCM interpretation.
- Use trace.json when explaining Rijndael process steps.
