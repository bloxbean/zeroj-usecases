# Annotated Private Voting

This example shows a privacy-preserving voting circuit written with ZeroJ symbolic annotations.

The voter proves:

- `voteChoice` is a boolean because it is a `ZkBool`.
- The private voter secret is in a public BLS12-381 Poseidon voter registry
  Merkle root.
- The public BLS12-381 Poseidon vote commitment was derived from the private
  vote and nullifier.
- The public BLS12-381 Poseidon nullifier hash was derived from the private
  nullifier and election id.

The circuit source is in `src/main/java/.../circuit/PrivateVoteProof.java`. The generated
`PrivateVoteProofCircuit` companion exposes `build`, `schema`, `inputs`, `publicInputs`, and
`calculateWitness`.

Run:

```bash
./gradlew test
./gradlew run
```
