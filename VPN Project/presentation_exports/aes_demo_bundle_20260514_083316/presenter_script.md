# Presenter Script

## Slide 1 - Goal

- Today I am demonstrating the Rijndael Process path of the AES simulator.
- The selected mode is CBC with a 128-bit key.
- The goal is to show plaintext input, encryption output, and what changes depending on the mode or engine.

## Slide 2 - Inputs

- This plaintext is: BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!
- The IV or nonce shown in the simulator is: f490e3d07040563a8e80b93e48cfe3cf.
- Additional authenticated data is: None.

## Slide 3 - Packet

- Here I focus on the encrypted packet JSON.
- I point out the mode, IV or nonce, ciphertext, and any tag or trace metadata.
- The packet currently includes keys: algorithm, mode, iv, ciphertext, tag, aad, trace, engine, key_size_bits.

## Slide 4 - Decryption

- After decryption, the simulator returns: BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!BLOCK-16-REPEAT!.
- This confirms the round-trip when the correct key and supporting values are used.

## Slide 5 - Pattern Leakage

- The comparison output helps explain why ECB leaks patterns while CBC and GCM hide repetition better.
- I use this slide to connect the simulator output to secure mode selection.

## Slide 6 - Rijndael Trace

- The exported trace contains 9 trace entries for the current packet.
- I use this to discuss AddRoundKey, SubBytes, ShiftRows, MixColumns, and why the final round differs.
