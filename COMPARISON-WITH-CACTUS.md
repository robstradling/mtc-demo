# Comparison: mtc-demo vs mcpherrinm/cactus

**Date:** 2025-06-02.
**Spec version:** draft-ietf-plants-merkle-tree-certs-04.

This document compares the `mtc-demo` implementation against the
`mcpherrinm/cactus` reference implementation of Merkle Tree Certificates.
It identifies behavioral differences, bugs, conformance gaps, and
spec ambiguities surfaced by the comparison.

**Severity key:**
- **[BUG]** — produces incorrect output or violates a MUST.
- **[GAP]** — missing validation or feature that the spec requires.
- **[COMPAT]** — wire-compatible but architecturally different; no interop issue.
- **[SCOPE]** — out of scope for mtc-demo but present in cactus.

---

## 1. Bugs in mtc-demo

### 1.1 [BUG] [FIXED] Serial number overflow for log\_number ≥ 32768

`cert.go` computes the serial as:

```go
serial := (int64(logNumber) << 48) | int64(index)
```

`int64` overflows for `logNumber ≥ 0x8000` (32768), producing a negative
value.  `AddASN1Int64` then encodes a negative INTEGER, violating
RFC 5280 §4.1.2.2 ("CAs MUST force the serialNumber to be a
non-negative integer") and the draft's statement that serials are
"positive and at most 2^64−1."

**cactus** uses `*big.Int` when parsing serials and `uint64` when
constructing them, correctly handling the full 1–65535 log-number range.

**Fix:** use `uint64` arithmetic and encode via `AddASN1BigInt`.

### 1.2 [BUG] [FIXED] MTCProof parser accepts trailing bytes

`UnmarshalMTCProof` in `cert.go` does not check whether the
`cryptobyte.String` is empty after consuming the `signatures` vector.
A proof with appended garbage is silently accepted.

**cactus** rejects trailing bytes:

```go
if !s.Empty() {
    return nil, fmt.Errorf("MTCProof: %d trailing bytes", len(s))
}
```

§6.1 implicitly requires full consumption (the structure is
length-delimited by the BIT STRING).

### 1.3 [BUG] [FIXED] MTCProof parser does not validate extension ordering

`UnmarshalMTCProof` stores the extensions vector as raw bytes without
checking the §5.2.1 requirement that elements "MUST be appear in
ascending order by extension\_type" with no duplicates.  A parser
"MUST reject" violations per §5.2.1.

**cactus** (`parseEntryExtensions`) validates ascending order and
rejects duplicates.

### 1.4 [BUG] [FIXED] MTCProof parser accepts empty cosigner\_id

`UnmarshalMTCProof` does not reject a zero-length `cosigner_id`
(TrustAnchorID `<1..2^8-1>` mandates at least one byte).

**cactus** explicitly checks `len(idBytes) == 0`.

---

## 2. Conformance gaps in mtc-demo

### 2.1 [GAP] [FIXED] Inclusion-proof length not checked at parse time

`UnmarshalMTCProof` stores the inclusion proof as raw bytes without
verifying that `len(inclusionProof) % HashSize == 0`.  The check is
deferred to `EvaluateSubtreeInclusionProof`, but a malformed proof
could propagate through serialization/round-trip logic before reaching
evaluation.

**cactus** validates at parse time in `ParseMTCProof`.

### 2.2 [GAP] [FIXED] TrustAnchorID arc size limited to uint32

`ParseTrustAnchorID` uses `ParseUint(…, 32)` and `appendBase128` takes
`uint32`, limiting OID arc values to 2^32−1.

**cactus** uses `uint64` for arcs, matching the RELATIVE-OID encoding
capacity (base-128 supports arcs up to 2^63 in practice).

### 2.3 [GAP] [FIXED] No ML-DSA signature support

mtc-demo supports ECDSA P-256/P-384 and Ed25519 for cosigning.

The MTC-with-tlog profile (`mtc-tlog-draft.md`) requires ML-DSA-44 for
all cosigners.  **cactus** is ML-DSA-44-only (using Go 1.27's
`crypto/mldsa`).

Certificates produced by mtc-demo with ECDSA cosignatures are valid per
the core draft (§5.3.3 "any PKIX signature algorithm MAY be used") but
cannot interoperate with a cactus verifier that expects ML-DSA-44.

---

## 3. Compatible differences (no interop impact)

### 3.1 [COMPAT] TrustAnchorID internal representation

| | mtc-demo | cactus |
|---|---|---|
| In-memory | Binary (base-128 RELATIVE-OID octets) | ASCII dotted-decimal (e.g. `"32473.1"`) |
| Wire (MTCProof.cosigner\_id) | Used directly | Converted via `Binary()` |
| Display / OIDName | Converted via `String()` | Used directly + prefix |

The on-wire encoding is identical: both emit RELATIVE-OID content octets
as the `cosigner_id` and produce the same `oid/1.3.6.1.4.1.<rel>`
cosigner\_name strings.

### 3.2 [COMPAT] MTCProof.Extensions storage

| | mtc-demo | cactus |
|---|---|---|
| Type | `[]byte` (raw, including 2-byte length prefix) | `[]MerkleTreeCertEntryExtension` (structured) |
| Marshal | `AddBytes(p.Extensions)` | `AddUint16LengthPrefixed(…)` over each ext |
| Unmarshal | Store raw bytes | Parse into typed structs |

Wire output is byte-identical for the same logical extensions.

### 3.3 [COMPAT] Entry hash computation path

mtc-demo builds a complete `MerkleTreeCertEntry` (extensions + type +
data) as `[]byte`, then calls `HashEntry → HashLeaf → HASH(0x00 || entry)`.

cactus streams the components directly into the hasher in `EntryHashExt`:
`HASH(0x00 || ext_vec || type || tbsContents)`.

Numerically identical.  cactus additionally implements the §7.2
single-pass optimization (`SinglePassEntryHash`), which mtc-demo omits.

### 3.4 [COMPAT] Inclusion-proof evaluation inner-loop guard

Both implementations add a guard to the §4.3.2 step 4.2.2 inner loop
("Until LSB(fn) is set, right-shift fn and sn equally"), which would
otherwise loop forever when `fn == 0`:

| | mtc-demo | cactus |
|---|---|---|
| Guard | `fn != 0` | `sn != 0` |

For valid subtrees, `fn == sn` when the inner loop executes, so the two
guards are equivalent.  Both correctly prevent the infinite loop the
spec's wording allows.

### 3.5 [COMPAT] Cosigner-ID ordering (shortlex)

Both implement the §6.1 shortlex order — shorter byte strings first,
then lexicographic — over the binary `cosigner_id` bytes.

cactus's SPEC-REVIEW.md notes (§1.2) that the spec under-specifies this
comparator (it is not plain `memcmp`), but both implementations agree.

### 3.6 [COMPAT] FindSubtrees return shape

mtc-demo returns `(left, right Interval, single bool, err error)`.
cactus returns `[]Subtree` (length 1 or 2).

Algorithmically identical.  Both always return two subtrees for
intervals of size > 1, per the §4.5 Python reference code.

### 3.7 [COMPAT] CosignedMessage format

Both marshal the §5.3.1 CosignedMessage identically:
`label(12) || cosigner_name(u8-prefixed) || timestamp(u64=0) || log_origin(u8-prefixed) || start(u64) || end(u64) || subtree_hash(32)`.

### 3.8 [COMPAT] Issuer DN construction

Both use the experimental form from §5.1:

- Attribute type: OID `1.3.6.1.4.1.44363.47.1` (`id-rdna-trustAnchorID`)
- Attribute value: `UTF8String` containing the trust anchor ID's
  relative dotted-decimal ASCII (e.g. `"32473.1"`)

### 3.9 [COMPAT] Null entry encoding

Both produce `[0x00, 0x00, 0x00, 0x00]` (2-byte empty extensions +
2-byte `null_entry` type).

### 3.10 [COMPAT] Experimental OIDs

Both use the same experimental-arc OIDs from the draft:

| OID | Name |
|---|---|
| `1.3.6.1.4.1.44363.47.0` | `id-alg-mtcProof` |
| `1.3.6.1.4.1.44363.47.1` | `id-rdna-trustAnchorID` |
| `1.3.6.1.4.1.44363.47.2` | `id-pe-mtcCertificationAuthority` |

---

## 4. Scope differences

### 4.1 [SCOPE] Features in cactus but not mtc-demo

| Feature | Spec section | Notes |
|---|---|---|
| ML-DSA-44/65/87 signing | Profile, FIPS 204 | mtc-demo uses ECDSA/Ed25519 |
| signed-note checkpoints | tlog-checkpoint | mtc-demo has no checkpoint format |
| tlog-tiles serving | tlog-tiles | mtc-demo stores trees in memory |
| ACME server | MTC §9 | mtc-demo has no ACME integration |
| Mirror/follower | tlog-mirror | Not in scope for mtc-demo |
| sign-subtree API | tlog-witness PR #245 | Not in scope |
| CA certificate (§5.5) | MTC §5.5 | mtc-demo does not build CA certs |
| Single-pass entry hash | MTC §7.2 | Optimization; mtc-demo uses step-by-step |
| Landmark HTTP endpoint | MTC §6.3.3 | mtc-demo has landmark data model only |
| Revoked-range seeding from minSerial | MTC §7.1 | mtc-demo has the data model |

### 4.2 [SCOPE] Design choices in mtc-demo not in cactus

| Feature | Notes |
|---|---|
| In-memory Merkle tree with precomputed levels | cactus uses tile-based on-disk storage via `golang.org/x/mod/sumdb/tlog` |
| ECDSA / Ed25519 cosigning | cactus is ML-DSA-44 only per the profile |
| `MerkleTree.SubtreeInclusionProof` proof generation | cactus derives proofs from tiles; mtc-demo generates from precomputed levels |

---

## 5. Spec ambiguities surfaced

These are issues where the spec is silent or ambiguous, and the two
implementations happen to agree (or diverge harmlessly).  See also
cactus's comprehensive `SPEC-REVIEW.md`.

| # | Issue | Both agree? |
|---|---|---|
| 1 | §7.2 single-pass omits `0x00` leaf prefix (SPEC-REVIEW §1.1) | Yes — both include `0x00` |
| 2 | §6.1 cosigner\_id shortlex comparator (SPEC-REVIEW §1.2) | Yes — length-first then lexicographic |
| 3 | §7.2 SPKI hash OCTET STRING framing (SPEC-REVIEW §1.3) | Yes — both emit `04 L H` |
| 4 | Empty-tree hash (SPEC-REVIEW §1.6) | cactus uses `SHA-256("")`; mtc-demo does not handle empty trees explicitly |
| 5 | §4.3.2 inner-loop termination guard | Both add guards; mtc-demo uses `fn!=0`, cactus uses `sn!=0` |
| 6 | Checkpoint vs subtree signatures (SPEC-REVIEW §2.1/2.2) | Both use `timestamp=0` subtree signatures in MTCProof |

---

## 6. Summary

| Category | Count | Items |
|---|---|---|
| Bugs in mtc-demo | 4 | §1.1–§1.4 |
| Conformance gaps | 3 | §2.1–§2.3 |
| Compatible differences | 10 | §3.1–§3.10 |
| Scope differences | 2 | §4.1–§4.2 |
| Spec ambiguities | 6 | §5 |

The two implementations are **wire-compatible** for the structures they
both produce (MTCProof, MerkleTreeCertEntry, CosignedMessage, issuer DN,
TrustAnchorID encoding).  The main blockers to full end-to-end
interoperability are:

1. **Signature algorithm mismatch** — mtc-demo's ECDSA/Ed25519
   cosignatures cannot be verified by a cactus ML-DSA-44 verifier
   (and vice versa).
2. **Serial number overflow** — mtc-demo produces invalid (negative)
   serials for `logNumber ≥ 32768`.
3. **Parser leniency** — mtc-demo accepts malformed MTCProofs that
   cactus (correctly) rejects.
