# Presentation Day Checklist

## Before Class Starts

Open all of these before anyone is waiting on you:

1. `AESSimulator.py`
2. Browser fallback from `presentation_web/`
3. Your slide deck
4. The `presentation_exports/` folder
5. This `presentation_reference/` folder

## Launch Commands

Main simulator:

```bash
cd "/Users/ryanellis/SU/COSC 370/Project/Cryptography/VPN Project"
python3.13 AESSimulator.py
```

Browser fallback:

```bash
cd "/Users/ryanellis/SU/COSC 370/Project/Cryptography/VPN Project/presentation_web"
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

## Rehearsal Order

Click through these presets once before presenting:

1. `Standard CBC Walkthrough`
2. `Standard GCM Integrity Demo`
3. `Rijndael Trace Walkthrough`
4. `Pattern Leakage Demo`

## Export Bundles To Prepare Slides

For each preset you plan to present:

1. Load the preset
2. Click `Export Slide Bundle`

Files produced:

1. `slide_notes.md`
2. `presenter_script.md`
3. `packet.json`
4. `plaintext.txt`
5. `decrypted_output.txt`
6. `comparison.txt`
7. `trace.json` when available

## If The Tkinter App Fails Live

Immediately switch to the browser fallback.

Use:

1. `Load Preset`
2. `Encrypt`
3. `Decrypt`
4. `Explain Mode Choice`
5. `Load Trace JSON`

## If You Freeze During The Talk

Use one of these anchor lines:

- CBC: "This shows how plaintext becomes ciphertext using a key and IV, then decrypts back correctly."
- GCM: "This adds integrity protection through the authentication tag."
- Rijndael Process: "This is the algorithm-focused view that supports discussing AES round transformations."
- Pattern Leakage: "This demonstrates that the encryption mode affects how much structure leaks."

## Recommended Strategy

Use:

1. Tkinter app as the main live demo
2. PowerPoint for framing and summary
3. Exported slide bundles for supporting material
4. Browser fallback only if needed
