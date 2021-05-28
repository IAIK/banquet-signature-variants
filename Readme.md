# Variants of the Banquet Signature Scheme

This repository contains the code for three variants of the Banquet signature scheme [[1]](#1) which were proposed and benchmarked in our paper

**Shorter Signatures Based on Tailor-Made Minimalist Symmetric-Key Crypto**  
*Christoph Dobraunig and Daniel Kales and Christian Rechberger and Markus Schofnegger and Greg Zaverucha*  
[eprint](https://eprint.iacr.org/2021/692)

The implementation of the **Rainier** signature scheme can be found [here](https://github.com/IAIK/rainier-signatures).

## Variants

The individual folders contain a Readme on how to run and perform the benchmarks.

* [`em-banquet`](em-banquet): Banquet using an Even-Mansour variant of AES.
* [`lsaes-banquet`](lsaes-banquet): Banquet using a variant of AES with 32-bit S-Boxes.
* [`em-lsaes-banquet`](em-lsaes-banquet): Banquet using a an Even-Mansour variant of AES with 32-bit S-Boxes.


## References

<a id="1">[1]</a>
**Banquet: Short and Fast Signatures from AES**
*Carsten Baum, Cyprien Delpech de Saint Guilhem, Daniel Kales, Emmanuela Orsini, Peter Scholl and Greg Zaverucha*, Public Key Cryptography 2021
[Paper](https://eprint.iacr.org/2021/068), [Implementation](https://github.com/dkales/banquet)
