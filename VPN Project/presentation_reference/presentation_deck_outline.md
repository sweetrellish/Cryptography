# 6-Slide Deck Outline

## Slide 1 - Project Goal

Title:
AES Demonstration: Modes, Integrity, and Rijndael Process

Bullets:

- Demonstrates AES encryption and decryption in a classroom-friendly simulator
- Compares Standard AES modes like CBC and GCM
- Includes a Rijndael Process path for algorithm-focused explanation
- Shows both practical encrypted output and internal transformation concepts

## Slide 2 - Standard AES-CBC Demo

Bullets:

- Shows plaintext, key, IV, encrypted packet, and decrypted output
- Demonstrates confidentiality and block-based processing
- Explains the role of the IV in CBC

## Slide 3 - AES-GCM: Confidentiality Plus Integrity

Bullets:

- Adds authenticated encryption
- Shows ciphertext, nonce, AAD, and tag
- Explains why integrity matters during decryption

## Slide 4 - Rijndael Process Engine

Bullets:

- Focuses on AES-128 CBC for teaching the algorithm
- Supports trace export for discussion of round operations
- Connects the class focus to concrete transformation steps

## Slide 5 - Why AES Mode Selection Matters

Bullets:

- ECB reveals repeated structure
- CBC hides repetition better but lacks built-in integrity
- GCM hides structure and adds authentication

## Slide 6 - Main Takeaways

Bullets:

- AES security depends on both the cipher and the mode
- GCM is generally the recommended modern choice
- Rijndael Process mode helps explain internal algorithm behavior
