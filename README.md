# Blinding a WOTS signature thanks to ZKBoo (MPC-in-the-head circuit)

This project implements a protocol based on **ZKBoo**, a zero-knowledge proof scheme. ZKBoo is designed to prove properties about data without revealing the data itself.

This project was carried out as part of my final internship for the Master's degree in Cryptology and Computer Security at [the University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the first half of 2025 at [UPC in Barcelona](https://www.upc.edu/ca), under the supervision of [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

### Project Structure

- `src/`: Contains the main source code.
- `README.md`: Project documentation.

### Third-Party Dependencies

This project includes a `third_party/` directory, which contains an older version of OpenSSL (1.0.2). This specific version was necessary to ensure compatibility with the original implementation from Aarhus University. 

### Help

To build the project, use the `make` command. This will generate four binaries:

1. `commitment_gen`: This binary is on the CLIENT side
                     It will get a random commitment key 'r' and print it in UPPERCASE hexadecimal (46
                     characters). After that, it will compute the commitment = SHA256(SHA256(m) || r) and print it in
                     UPPERCASE hexadecimal (64 characters).
                     No file.txt will be generated, you have to copy the output manually.

2. `sign`:  This binary is on the SERVER side and generates a WOTS signature for a given commitment.
            It will sign your previously-generated 256-bits commitment, using a WOTS algorithm.
            To this end, it will generate a random private key and a public key.
            Only the public key will be saved in 'public_key.txt', and you will need to build/verify the final blind 
            signature.
            Also, it will generate a file 'signature.txt' with the WOTS signature.
            You can then use the MPC prover to generate a proof of knowledge of the signature.

3. `prover`:  This binary is on the CLIENT side.
              It builds a ZKBoo-based zero-knowledge proof of knowledge of a WOTS signature of a secretly known
              256 bits message commitment, which one we know the key.
              The result will be saved in 'proof.bin'
              You will need to run the MPC verifier to verify the proof.

4. `verifier`: This binary is used by anyone to verify the zero-knowledge proof of knowledge stored in 'proof.bin'.
               This proof is used as a blind signature for a WOTS signature of a secretly known 256 bits message
               commitment. To verify the proof, we need the public key, stored in 'public_key.txt'.

### References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits (ePrint)](https://eprint.iacr.org/2016/163)
- [GitHub Repository for ZKBoo Implementation](https://github.com/Sobuno/ZKBoo) (original implementation, which only included a ZK proof of knowledge of a SHA256 preimage)