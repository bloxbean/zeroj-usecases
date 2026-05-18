# Annotated Proof Of Reserves

This example models a proof-of-reserves slice with symbolic annotations.

The exchange proves:

- A private customer liability leaf is included in the public liabilities root.
- The public asset value is greater than or equal to the public claimed liabilities.
- The private account balance is covered by the claimed liability total.

The circuit uses `@CircuitParam` and `@FixedSize(param = "depth")`, so the same Java source
can build different fixed-depth Merkle circuits.

Run:

```bash
./gradlew test
./gradlew run
```
