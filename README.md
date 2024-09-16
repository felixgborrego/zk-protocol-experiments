# Zero Knowledge Protocol experiments in Rust

An introductory exploration of Zero-Knowledge Protocols using zk-SNARK circuits.

This example demonstrates how to generate an encoded base64 token containing all the necessary information for a verifier to perform a ZK verification.

The implementation leverages the bellman crate to represent circuit computations and the pairing crate for constructing pairing-friendly elliptic curves.