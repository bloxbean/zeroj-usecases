# Annotated Compliance Credential

This example shows a selective-disclosure credential gate written with symbolic annotations.

The holder proves:

- The private age is greater than or equal to the public minimum age.
- The private country code equals the public required country code.
- The private sanctions-screen flag is true.
- The public BLS12-381 Poseidon credential commitment binds the private
  credential attributes and salt.

`ZkUInt` range constraints and `ZkBool` boolean constraints are added by the symbolic type factories,
so the circuit source reads like domain code while still producing concrete ZeroJ constraints.

Run:

```bash
./gradlew test
./gradlew run
```
