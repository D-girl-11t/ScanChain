# Scan-Chain Attack on an AES-128 Hardware Core

Recovering the secret AES-128 key from a hardware AES core by reading its **design-for-test (DFT) scan chain**.

Individual mini-project for **EL 9453: Introduction to Hardware Security and Trust** at NYU Tandon (Spring 2023).

## Background

Scan chains link a chip's flip-flops into one long shift register, so testers can load and read internal state. On a crypto core, that same access leaks intermediate round values, and from those the key can be recovered. This holds even when the order of the flip-flops in the chain is scrambled.

The target was an iterative AES-128 core, emulated as a command-line binary, with these properties:

- It has a 256-bit scan chain: a 128-bit input register plus a 128-bit round (state) register.
- The bit order in the chain was randomized and unique to each student.
- The round-key ROM came from a secret key, also unique to each student.
- It is controlled with `-input` (plaintext), `-clocks` (1 = load input, 2–10 = rounds) and `-emit_scan` (dump the scan chain after each clock).

The goal was to recover the original 128-bit encryption key, using only plaintext inputs, clock control and scan-chain dumps.

## Attack

`scanattack_aes.py` automates the attack in four steps.

### 1. Map the input register bits
Flip each of the 128 plaintext bits one at a time and clock once to load the input register. Each single-bit change moves exactly one scan-chain bit, which gives the position of every input bit in the chain.

### 2. Map the round (state) register bits
The 128 positions left over hold the state register. To find which state bit each one is, compare runs whose plaintexts differ by one bit: XOR the final outputs and XOR the scan chains. Intersecting the scan positions that change along with each output bit gives the position of that output bit in the chain.

### 3. Recover the round-0 key, one byte at a time
This step follows the method of Yang et al. (*Secure Scan*, IEEE TCAD 2006):

- For each key byte, apply plaintext pairs `2i` and `2i+1` for `i = 0…127`. These differ only in the LSB.
- Run one round (2 clocks) for each plaintext.
- XOR the two scan chains and count the differing state bits, which is the Hamming distance after SubBytes, ShiftRows and MixColumns.
- The Hamming distances **9, 12, 23 and 24** each occur for only one SubBytes input pair: (226,227), (242,243), (122,123) and (130,131). When one appears, `key_byte = plaintext_byte ⊕ sbox_input`.

This finds each key byte except its LSB.

### 4. Resolve the LSBs
That leaves 2¹⁶ candidate keys. Encrypt the all-zero block under each candidate with PyCryptodome, and keep the one that matches the core's output.

## Result

The attack recovered the full AES-128 key of the assigned core:

```
5261f823167e1cab01ac7f256c7a721c
```

## Running

The course-provided AES core binaries and the exam handout are **not included** in this repo.

```bash
pip install pycryptodome
# place the core binary next to the script, then
python scanattack_aes.py
```

The script calls `aes_scan_exam_<id>_windows_amd64.exe`. To use another platform, edit `execute()` to point at the Linux or macOS build.

## Skills

Hardware security · DFT / scan-chain architecture · AES-128 internals (SubBytes, ShiftRows, MixColumns, key schedule) · side-channel style key recovery · Python automation (`subprocess`, PyCryptodome)

## References

1. B. Yang, K. Wu, R. Karri, "Secure Scan: A Design-for-Test Architecture for Crypto Chips," *IEEE TCAD*, 2006.
2. S. S. Ali et al., "AES Design Space Exploration New Line for Scan Attack Resiliency," *IEEE VLSI-SoC*, 2014.
3. H. Pearce et al., "High-Level Approaches to Hardware Security: A Tutorial," *ACM TECS*, 2023.
