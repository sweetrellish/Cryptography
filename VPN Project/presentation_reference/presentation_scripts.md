# Presentation Scripts

## 5-Minute Version

### Opening

"Today I’m showing an AES demonstration tool built for our cryptography class. The purpose is to show both the practical use of AES modes and, separately, the internal Rijndael process that AES is based on."

### CBC Demo

"In this first preset, I’m using the Standard Cipher Block Chaining Walkthrough. CBC is useful for demonstrating block encryption with an Initialization Vector (IV). Here the plaintext is entered, the key and IV are shown, and after encryption the simulator produces a JSON packet containing the ciphertext and metadata. Then I decrypt it to show that the original plaintext comes back correctly."

### GCM (Galois/Counter Mode) Demo

"In the second preset, I switch to Standard GCM Integrity Demo. GCM provides both confidentiality and integrity. The packet includes a tag, and that tag is used during decryption to verify that the data has not been changed."

### Rijndael Process Demo

"Now I switch to the Rijndael Trace Walkthrough. This is the teaching-focused part of the simulator. Instead of only showing the final ciphertext, this engine can export trace data so I can talk about AddRoundKey, SubBytes, ShiftRows, and MixColumns."

### Pattern Demo

"Finally, the pattern leakage demo helps explain why ECB is insecure for structured plaintext and why CBC and GCM are better choices."

### Conclusion

"The main takeaway is that AES is not just one black-box operation. The mode changes the security behavior, and the Rijndael Process view helps explain how the encryption transforms data internally."

## 10-Minute Version

### Introduction

"This project is an AES teaching simulator built in Python with a Tkinter interface. It supports two goals: demonstrating real AES usage with common modes like CBC and GCM, and supporting the course focus on the actual Rijndael process through a trace-capable teaching engine."

### Interface Overview

"At the top of the simulator, I can choose the engine, mode, and key size. I can generate keys and IVs, enter plaintext, and see the encrypted packet and decrypted output. There is also a mode comparison lab and an export tool for presentation bundles."

### CBC Walkthrough

"I’ll start with the Standard CBC Walkthrough preset. CBC is useful for teaching because it clearly shows block-based encryption with an IV. The IV helps ensure that the same plaintext does not encrypt identically each time. After encryption, the simulator creates a packet containing the mode, IV, ciphertext, and key size metadata. After that, decryption shows the message returning to its original form."

### GCM Walkthrough

"Now I switch to the Standard GCM Integrity Demo. GCM is an authenticated encryption mode. That means it not only encrypts the data but also verifies whether it has been modified. The important fields here are the nonce, ciphertext, AAD, and authentication tag."

### Rijndael Walkthrough

"Now I move to the Rijndael Trace Walkthrough. This is the mode that supports the course focus on how AES actually works internally. The simulator exports trace data so I can discuss AddRoundKey, SubBytes, ShiftRows, MixColumns, and the round structure."

### Pattern Leakage

"The final preset is the Pattern Leakage Demo. This shows why the mode matters. ECB can leak repeated-block patterns, while CBC and GCM reduce that visible structure. GCM also adds integrity protection."

### Conclusion (10min)

"The simulator demonstrates practical AES usage, the security impact of different modes, and the internal Rijndael process. That combination makes it useful both as a demo and as a teaching tool."
