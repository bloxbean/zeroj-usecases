#!/usr/bin/env python3
"""Independent reference for the private-ballot tally (zeroj-usecases ADR-0005).

Re-implements Jubjub and exponential ElGamal from the curve definition alone, without ZeroJ, and
prints fixed vectors for ElGamalReferenceVectorsTest to compare against the Java implementation.

Curve: twisted Edwards  -u^2 + v^2 = 1 + d*u^2*v^2  over the BLS12-381 scalar field p,
       d = -(10240/10241) mod p (Zcash protocol specification, section 5.4.9.3).
G:     the pedersen-jubjub-v1 value base, [8]*(u0, 11); checked against the value pinned in
       ZeroJ docs/specs/pedersen-jubjub-v1.md.

Run: python3 elgamal_reference.py > reference-output.txt
"""
import hashlib

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
D = (-10240 * pow(10241, P - 2, P)) % P
assert D == 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1

O = (0, 1)


def add(p1, p2):
    (u1, v1), (u2, v2) = p1, p2
    t = D * u1 * u2 * v1 * v2 % P
    u3 = (u1 * v2 + v1 * u2) * pow(1 + t, P - 2, P) % P
    v3 = (v1 * v2 + u1 * u2) * pow(1 - t, P - 2, P) % P   # a = -1
    return (u3, v3)


def neg(p1):
    return ((-p1[0]) % P, p1[1])


def mul(k, p1):
    acc, base = O, p1
    while k > 0:
        if k & 1:
            acc = add(acc, base)
        base = add(base, base)
        k >>= 1
    return acc


def on_curve(p1):
    u, v = p1
    return (v * v - u * u - 1 - D * u * u * v * v) % P == 0


G = mul(8, (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11))
assert on_curve(G) and mul(L, G) == O
assert G[0] == 0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5


def scalar(tag, i):
    digest = hashlib.sha256(("zeroj.usecases.elgamal.reference." + tag).encode() + bytes([i])).digest()
    return int.from_bytes(digest, "big") % L


def emit(name, p1):
    print(f"{name} {p1[0]:064x} {p1[1]:064x}")


sks = [scalar("sk", j) for j in range(1, 4)]
pks = [mul(sk, G) for sk in sks]
pk = O
for pk_j in pks:
    pk = add(pk, pk_j)

votes = [1, 0, 1, 1, 0]
ks = [scalar("k", i) for i in range(1, 6)]
sum_a, sum_b = O, O
print(f"scalar sk1 {sks[0]:064x}")
print(f"scalar sk2 {sks[1]:064x}")
print(f"scalar sk3 {sks[2]:064x}")
for i, (v, k) in enumerate(zip(votes, ks), start=1):
    a = mul(k, G)
    b = add(mul(v, G), mul(k, pk))
    print(f"scalar k{i} {k:064x}")
    print(f"vote v{i} {v}")
    emit(f"A{i}", a)
    emit(f"B{i}", b)
    sum_a, sum_b = add(sum_a, a), add(sum_b, b)

emit("G", G)
for j, pk_j in enumerate(pks, start=1):
    emit(f"PK{j}", pk_j)
emit("PK", pk)
emit("sumA", sum_a)
emit("sumB", sum_b)
m = sum_b
for j, sk in enumerate(sks, start=1):
    d_j = mul(sk, sum_a)
    emit(f"D{j}", d_j)
    m = add(m, neg(d_j))
emit("M", m)
tally = next(t for t in range(len(votes) + 1) if mul(t, G) == m)
assert tally == sum(votes)
print(f"tally T {tally}")
