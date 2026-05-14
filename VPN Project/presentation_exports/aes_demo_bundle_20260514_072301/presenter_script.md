# Presenter Script

## Slide 1 - Goal

- Today I am demonstrating the Rijndael Process path of the AES simulator.
- The selected mode is CBC with a 128-bit key.
- The goal is to show plaintext input, encryption output, and what changes depending on the mode or engine.

## Slide 2 - Inputs

- This plaintext is: 
- The IV or nonce shown in the simulator is: generated in app.
- Additional authenticated data is: None.

## Slide 3 - Packet

- Here I focus on the encrypted packet JSON.
- I point out the mode, IV or nonce, ciphertext, and any tag or trace metadata.
- The packet currently includes keys: none yet.

## Slide 4 - Decryption

- After decryption, the simulator returns: no decrypted output exported yet.
- This confirms the round-trip when the correct key and supporting values are used.
