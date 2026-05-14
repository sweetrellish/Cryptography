# Slides 17-24 Cross Reference

This file maps slides 17 through 24 of `Cryptography Presentation.pdf` to the AES simulator, browser fallback, and recommended presentation language.

## Slide 17 - AES Demo

Purpose:

- Transition from theory into the live demo.

Best supporting material:

- `AESSimulator.py`
- Preset: `Standard CBC Walkthrough`

What to say:

- "The next section connects the theory from the deck to the AES simulator."
- "I will show standard AES usage first, then the Rijndael process view, and then mode selection."

## Slide 18 - AES Decryption Process

Slide topic:

- Inverse SubBytes
- Inverse ShiftRows
- Inverse MixColumns
- AddRoundKey in reverse round-key order

Best supporting material:

- `AESSimulator.py`
- Preset: `Rijndael Trace Walkthrough`
- Exported `trace.json`
- Browser fallback trace viewer in `presentation_web/index.html`

What to say:

- "AES decryption reverses the transformations used during encryption."
- "The decryption sequence uses the inverse operations and applies round keys in reverse order."
- "This is the slide most directly supported by the Rijndael Process engine."

Recommendation:

- Use the simulator briefly, then show exported trace data rather than trying to narrate every internal state live from memory.

## Slide 19 - DES vs AES

Slide topic:

- DES key size vs AES key size
- Performance/security comparison

What to correct while speaking:

- DES key space is `2^56`, not `256`.
- AES key spaces are `2^128`, `2^192`, and `2^256`.
- AES is the modern secure standard; DES is obsolete outside legacy contexts.

Best supporting material:

- No heavy live demo required.
- Optional quick pointer to the key size selector in `AESSimulator.py`.

What to say:

- "DES is no longer considered secure because its 56-bit key is too small."
- "AES uses far larger key sizes and is the modern standard for secure symmetric encryption."

## Slide 20 - Strengths of AES

Slide topic:

- Brute-force resilience
- Open public scrutiny

Best supporting material:

- `AESSimulator.py`
- Key size selector

What to say:

- "AES-128 already has an infeasibly large key space for brute-force attacks."
- "Another strength is that AES has been extensively studied publicly rather than relying on secrecy."

Recommendation:

- Prefer "computationally infeasible" over extremely specific timing estimates unless the source is cited directly on the slide.

## Slide 21 - Weaknesses of AES

Slide topic:

- Practical weaknesses due to implementation or configuration
- Side-channel risks
- Human error and key handling

Best supporting material:

- Conceptual tie to GCM and key-management discussion
- No large live demo needed

What to say:

- "AES is strong as an algorithm, but systems can still fail because of poor configuration, leaked keys, side-channel attacks, or implementation mistakes."
- "In practice, many real weaknesses are outside the cipher itself."

Recommendation:

- Avoid vague wording like "seeing how it operates using different keys" unless you can name the attack model clearly.

## Slide 22 - Key Management

Slide topic:

- Secure key storage, exchange, and rotation

Best supporting material:

- `AESSimulator.py`
- Key input field

What to say:

- "In the simulator, I enter the key directly because it is a teaching tool."
- "In real systems, key management is one of the hardest and most important parts of security."
- "Even a strong cipher becomes useless if the key is exposed."

## Slide 23 - Mode of Operation

Slide topic:

- ECB, CBC, GCM
- Why block ciphers need modes for larger data

Best supporting material:

- `AESSimulator.py`
- Presets: `Standard CBC Walkthrough`, `Standard GCM Integrity Demo`, `Pattern Leakage Demo`

What to say:

- "AES is a block cipher, so the way it is applied matters."
- "ECB encrypts blocks independently and can reveal patterns."
- "CBC adds chaining and an IV."
- "GCM adds authenticated encryption."

## Slide 24 - Which Mode Is Recommended?

Slide topic:

- ECB insecure
- CBC usable but incomplete
- GCM modern standard

Best supporting material:

- `Pattern Leakage Demo`
- `Standard GCM Integrity Demo`

What to say:

- "ECB is insecure because it reveals structure."
- "CBC improves confidentiality, but by itself it does not provide integrity."
- "GCM is generally the best modern choice because it combines encryption and authentication."

## Strongest App Mappings

The slides most directly supported by the simulator are:

1. Slide 18: AES decryption process / Rijndael process trace
2. Slide 23: mode of operation
3. Slide 24: recommended mode choice

The more theory-oriented slides are 19 through 22. Use the simulator only lightly on those slides.
