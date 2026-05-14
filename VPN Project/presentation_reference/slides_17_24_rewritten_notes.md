# Rewritten Speaking Notes For Slides 17-24

These are cleaner spoken versions of the deck content, tuned to match the simulator and to avoid weak or inaccurate phrasing.

## Slide 17 - AES Demo

"This section is where I connect the presentation to the simulator. I am going to show AES in two ways: first through standard modes like CBC and GCM, and second through a Rijndael Process mode that helps explain the internal algorithmic steps."

## Slide 18 - AES Decryption Process

"AES decryption works by applying inverse versions of the encryption transformations. That includes inverse SubBytes, inverse ShiftRows, inverse MixColumns, and AddRoundKey using the round keys in reverse order. In my simulator, this idea is represented most clearly through the Rijndael Process engine and the exported trace data, which helps explain how decryption reconstructs the original plaintext from ciphertext."

## Slide 19 - DES vs AES

"DES and AES are both symmetric ciphers, but AES is the modern standard. DES uses a 56-bit key, which is far too small for modern security. AES uses 128-bit, 192-bit, or 256-bit keys, which creates dramatically larger key spaces. Because of that, AES provides much stronger security and is the practical modern replacement for DES."

## Slide 20 - Strengths of AES

"One major strength of AES is that brute-force attack becomes computationally infeasible at modern key sizes. AES is also strong because it has been openly studied by the cryptography community for years, which means experts have had extensive opportunities to analyze it for weaknesses."

## Slide 21 - Weaknesses of AES

"AES is strong as a cipher, but real systems can still fail because of side-channel attacks, weak implementations, exposed keys, or human configuration mistakes. So the practical weaknesses of AES systems are often not in the core algorithm itself, but in how the system is built and operated."

## Slide 22 - Key Management

"Key management is critical because the security of AES depends entirely on protecting the encryption key. If the key is weak, leaked, or improperly stored, then the system becomes vulnerable even if the algorithm is strong. That is why secure exchange, storage, and rotation policies are essential in real deployments."

## Slide 23 - Mode of Operation

"AES is a block cipher, so it needs a mode of operation to securely handle data larger than one block. Different modes produce different security behavior. ECB encrypts blocks independently and can reveal patterns. CBC introduces chaining through the previous block and an IV. GCM provides authenticated encryption, which means it protects both confidentiality and integrity."

## Slide 24 - Which Mode Is Recommended?

"Among these modes, ECB is insecure and should not be used for sensitive structured data because it reveals patterns. CBC is better for confidentiality, but by itself it does not provide integrity protection. GCM is generally the best modern choice because it combines encryption and authentication in one mode."
