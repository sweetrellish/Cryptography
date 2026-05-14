# Presenter Script

## Slide 1 - Goal

- Today I am demonstrating the Standard path of the AES simulator.
- The selected mode is CBC with a 128-bit key.
- The goal is to show plaintext input, encryption output, and what changes depending on the mode or engine.

## Slide 2 - Inputs

- This plaintext is: Meet at 5 PM by the library steps.
- The IV or nonce shown in the simulator is: 0f0e0d0c0b0a09080706050403020100.
- Additional authenticated data is: None.

## Slide 3 - Packet

- Here I focus on the encrypted packet JSON.
- I point out the mode, IV or nonce, ciphertext, and any tag or trace metadata.
- The packet currently includes keys: mode, iv, ciphertext, tag, aad, engine, key_size_bits.

## Slide 4 - Decryption

- After decryption, the simulator returns: Meet at 5 PM by the library steps..
- This confirms the round-trip when the correct key and supporting values are used.

## Slide 5 - Pattern Leakage

- The comparison output helps explain why ECB leaks patterns while CBC and GCM hide repetition better.
- I use this slide to connect the simulator output to secure mode selection.
