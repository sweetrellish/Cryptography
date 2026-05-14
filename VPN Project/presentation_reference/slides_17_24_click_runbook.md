# Slide 17-24 Click Runbook

This file tells you exactly what to click in the simulator while each slide is on screen.

## Before Starting

Open the simulator:

```bash
cd "/Users/ryanellis/SU/COSC 370/Project/Cryptography/VPN Project"
python3.13 AESSimulator.py
```

Have the browser fallback ready too:

```bash
cd "/Users/ryanellis/SU/COSC 370/Project/Cryptography/VPN Project/presentation_web"
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## Slide 17 - AES Demo

Clicks:

1. In `Presentation Preset`, choose `Standard CBC Walkthrough`
2. Click `Load Preset`

What to point at:

1. Engine selector
2. AES Mode
3. Plaintext box

## Slide 18 - AES Decryption Process

Clicks:

1. Choose `Rijndael Trace Walkthrough`
2. Click `Load Preset`
3. Point to `Include process trace`
4. Click `Export Slide Bundle` if you want to show where `trace.json` comes from

Optional fallback:

1. Open the browser demo
2. Click `Load Trace JSON`
3. Select exported `trace.json`

## Slide 19 - DES vs AES

Clicks:

1. No major simulator action needed
2. Optionally point at `Key Size (bits)` in the app

Goal:

- Use this mainly as a theory slide

## Slide 20 - Strengths of AES

Clicks:

1. Point at `Key Size (bits)` selector
2. Optionally point at `Engine = Standard`

Goal:

- Reinforce that AES uses large key sizes and is practical in modern systems

## Slide 21 - Weaknesses of AES

Clicks:

1. Load `Standard GCM Integrity Demo`
2. Point at the packet `tag`

Goal:

- Connect implementation quality and integrity protection to real-world security

## Slide 22 - Key Management

Clicks:

1. Point at `Key (hex)` field
2. Point at `Generate Key + IV`

Goal:

- Explain that the simulator simplifies key entry for teaching, but real systems need secure key management

## Slide 23 - Mode of Operation

Clicks:

1. Load `Standard CBC Walkthrough`
2. Point at `AES Mode = CBC`
3. Load `Standard GCM Integrity Demo`
4. Point at `AES Mode = GCM`
5. Load `Pattern Leakage Demo`
6. If needed, click `Run Pattern Leakage Demo`

Goal:

- Show that the mode changes the security behavior, not just the output format

## Slide 24 - Which Mode Is Recommended?

Clicks:

1. Stay on `Pattern Leakage Demo`
2. Point at comparison output
3. If needed, reload `Standard GCM Integrity Demo` and point at the `tag`

Goal:

- End by reinforcing: ECB insecure, CBC incomplete, GCM recommended
