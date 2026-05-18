# ZK MPF Private Registry

This usecase shows how to build and test a private membership circuit for a
Cardano Client Lib MPF registry using ZeroJ symbolic annotations. It is a
witness-level demo: it builds the registry, derives MPF witness arrays, and
evaluates the BLS12-381 circuit. A practical Groth16 proof/Yaci flow for MPF is
deferred until the MPF circuit cost is reduced.

The public verifier sees only:

- `registryRoot`
- `keyPathNullifier`

The member key, value commitment, and MPF wire proof stay private inside the
symbolic circuit witness.

## Why Poseidon MPF?

CCL's normal MPF path is Blake2b-based and is compatible with the native Aiken
MPF verifier. This project uses the separate ZeroJ Poseidon MPF profile:

```text
CCL MpfTrie + ZeroJ Poseidon HashFunction
  -> CCL wire proof
  -> PoseidonMpfCodec witness arrays
  -> @ZKCircuit symbolic MPF verifier
  -> BLS12-381 circuit witness
```

The two roots are not interchangeable.

## Project Structure

- `PrivateRegistryMembership.java`: annotated circuit using `ZkMpf`.
- `PrivateRegistryDemo.java`: builds a CCL MPF registry, creates witness inputs,
  and calculates a BLS12-381 circuit witness.
- `PrivateRegistryMembershipCircuitTest.java`: verifies valid and invalid
  witnesses and checks that only root/nullifier are public.

## Run

Publish the current ZeroJ snapshot first:

```bash
cd /Users/satya/work/bloxbean/zeroj
./gradlew publishToMavenLocal
```

The default dependency version matches the local snapshot used when this
usecase was created. To test a freshly committed ZeroJ snapshot, pass the
commit-derived version explicitly:

```bash
./gradlew test -PzerojVersion=0.1.0-pre2-<commit>-SNAPSHOT
```

Then run the usecase:

```bash
cd /Users/satya/work/bloxbean/zeroj-usecases/zk-mpf-private-registry
./gradlew test
./gradlew run
```

## End-to-End Tutorial

1. Build a Poseidon-rooted CCL MPF registry:

```java
MpfTrie registry = PoseidonMpfTrie.inMemory();
registry.put(memberKey, memberValue);
registry.put(otherKey, otherValue);
```

2. Generate the CCL wire proof and convert it to symbolic witness arrays:

```java
byte[] proof = registry.getProofWire(memberKey).orElseThrow();
int maxSteps = Math.max(1, PoseidonMpfCodec.decode(proof).size());

PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(
        memberKey,
        proof,
        maxSteps,
        2);
```

3. Build the public inputs:

```java
int[] keyPath = witness.keyPath().stream()
        .mapToInt(BigInteger::intValueExact)
        .toArray();

BigInteger registryRoot = PoseidonMpfHash.fieldFromDigestBytes(registry.getRootHash());
BigInteger keyPathNullifier = PoseidonMpfHash.keyPathNullifier(
        PoseidonParamsBLS12_381T3.INSTANCE,
        keyPath);
```

4. Add private witness values:

```java
var inputs = new ZkInputMap()
        .put("registryRoot", registryRoot)
        .put("keyPathNullifier", keyPathNullifier)
        .put("value_commitment", PoseidonMpfValueCommitment.field(memberValue));
witness.putInto(inputs);
```

5. Build and evaluate the generated annotated circuit:

```java
var circuit = PrivateRegistryMembershipCircuit.build(maxSteps, 2);
circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381);
```

6. For Cardano on-chain use, generate a Groth16 BLS12-381 proof and verify it
   from a custom Julc validator through `Groth16BLS12381Lib.verify(...)`.
   The validator should also enforce application-specific state rules such as
   the accepted registry root and one-time nullifier use.

This project intentionally stops at witness evaluation. The existing ZeroJ
Groth16/Yaci examples show the proof submission pattern, but applying it to MPF
should wait until the MPF circuit is optimized enough for practical proving and
transaction costs.
