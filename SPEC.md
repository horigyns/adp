# ADP-1 — the Akaeon Declaration Protocol

*An open, vendor-independent format for machine-readable rights reservations against AI training and text-and-data-mining.*


> **What this document is.** The normative specification of **ADP-1**, an open
> format for declaring and verifying a reservation of rights against AI training
> and text-and-data-mining. It is the technical core of the Akaeon Registry; the
> [Registry technical specification](https://akaeon.com/docs/spec) describes one operator's
> implementation and its regulatory/audit framing, and points here for the
> on-the-wire format.
>
> **The one load-bearing property.** A third party can verify any ADP-1
> declaration *without trusting Akaeon at all.* Every section of this document
> is designed to survive the test: **does this still work if Akaeon is dead and
> its servers are gone?** If a mechanism fails that test, it is not in the
> normative core.
>
> **Ships with the spec, not after it:** a [reference verifier](#10-reference-verifier)
> in Python and JavaScript, and a set of [canonical test vectors](#9-conformance-test-vectors)
> (real declarations with real hashes, signatures, and inclusion proofs) the
> verifiers are tested against. Reference verifier and test vectors: [`verify.mjs`](./verify.mjs), [`verify.py`](./verify.py), [`test-vectors.json`](./test-vectors.json) in this repository.
>
> **Conformance language.** The key words MUST, MUST NOT, SHOULD, SHOULD NOT,
> and MAY are to be interpreted per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
> and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when in capitals.

---

## 1. Scope, versioning, and design goals

ADP-1 specifies three things and nothing more:

1. **A declaration** — the canonical record of what a rights reservation says
   (§4).
2. **An anchor** — how a declaration's digest is committed to a public,
   permanent log so its existence-by-a-certain-time is provable (§5).
3. **Discovery and verification** — how a crawler or lab finds the relevant
   declaration, and the exact, normative procedure to verify it (§6, §7).

The document is doing three jobs at once, and every section is built to serve at
least one: it is the technical artifact that makes the format submittable to a
standards process; it is the proof to early adopters that they are not locking
into a private dependency; and it is the cheap consumption format that lets a
lab check a declaration in about fifty lines of code.

### 1.1 Versioning

This regime is designed for a decade-scale horizon with a roughly two-year
review cycle, so versioning is not optional. Two independent version numbers
appear in every declaration:

- **`adp_version`** — the *protocol* version (this document is `"1.0"`). It
  governs the canonicalization rule, the signing construction, the anchor
  format, and the verification procedure. A verifier MUST refuse a declaration
  whose `adp_version` major number it does not implement.
- **`schema_version`** — the *declaration schema* version (this document
  defines `1`). It governs the field set and vocabulary. A new use category or
  content-identifier type bumps `schema_version` without touching
  `adp_version`. A verifier MAY accept a higher `schema_version` it does not
  fully understand **only** for the cryptographic checks (§7 steps 2–6 are
  schema-agnostic); it MUST NOT silently act on reservation semantics it does
  not understand.

The split exists so the expensive, security-critical machinery (canonical bytes,
signatures, Merkle/anchor) can stay frozen across many cheap vocabulary
revisions.

### 1.2 Design goals (and the non-goal)

| Goal | How ADP-1 meets it |
|---|---|
| **Verifiable without the issuer** | The verify path (§7) trusts only a hash function, an Ed25519 implementation, and a public Arweave gateway. |
| **Interoperate, don't compete** | Subject identifiers reference existing content-ID standards (§4.3); reservation semantics map one-to-one onto aipref and TDMRep (§8). |
| **Express "yes, under terms," not only "no"** | The reservation field is a superset that carries opt-in licensing offers and RSL compatibility (§8.4). |
| **Granular** | Reservations are per use-category and per actor (§4.4), fixing TDMRep's all-or-nothing weakness. |
| **Privacy-respecting on a permanent log** | Declarations embed identifiers and hashes, never personal data; pseudonymous keys and append-only supersession are first-class (§8.5). |

**Non-goal:** ADP-1 does not, and cannot, make a lab *honor* a reservation. It
makes an honoring lab's compliance *provable* and a publisher's reservation
*durable and authoritative*. Enforcement is a policy and legal matter; ADP-1 is
the evidentiary and interoperability substrate beneath it.

---

## 2. The three trust assumptions, stated nakedly

A specification whose security rests on hidden assumptions cannot be evaluated.
ADP-1 has exactly three, and they are the entire trust surface:

1. **The hash function (SHA-256) and signature scheme (Ed25519) are sound.**
   Standard cryptographic assumptions, shared with TLS, Certificate
   Transparency, and most of the modern web.
2. **Arweave provides permanence and a monotonic block timestamp.** A
   transaction included at block height *H* provably existed no later than that
   block's timestamp, and remains retrievable from the public network
   indefinitely. This is the only *external service* ADP-1 trusts.
3. **A declarant's authority proof means what it claims.** DNS control proves
   authority over a domain; a signature chain proves authorship of a work. ADP-1
   binds the declaration to one of these; the strength of the binding is the
   strength of the underlying proof (§5.6).

**What is explicitly NOT trusted: Akaeon.** Akaeon (or any registry operator)
batches declarations and serves inclusion proofs, but every claim it makes is
re-derivable by the verifier from (1)–(3). Akaeon can be offline, hostile, or
extinct and every declaration it ever anchored still verifies. §10's reference
verifier is the falsifiable proof of this claim.

---

## 3. Document layers at a glance

```
┌─ Layer 3 — DISCOVERY & VERIFICATION (§6, §7) ───────────────────────┐
│  find the declaration (DNS TXT · /.well-known · robots/TDMRep ext ·  │
│  content-id resolution · C2PA) → run the 7-step verify procedure     │
├─ Layer 2 — ANCHOR (§5) ──────────────────────────────────────────────┤
│  batch declarations into a Merkle tree (RFC 6962) · anchor only the  │
│  root to Arweave · each record carries its inclusion proof           │
├─ Layer 1 — DECLARATION (§4) ─────────────────────────────────────────┤
│  canonical record: versions · subject (domain/creator/work) ·        │
│  reservations (per use × per actor) · declarant + authority ·        │
│  temporal fields · declarant signature · JCS canonicalization        │
└──────────────────────────────────────────────────────────────────────┘
        cross-cutting: §8 interop · opt-in/RSL · privacy/GDPR · security
```

---

## 4. Layer one — the declaration

A **declaration** is the canonical record of a rights reservation. It is a JSON
document with a fixed field set, canonicalized deterministically (§4.7), hashed,
and signed by the declarant.

### 4.1 The full shape

A complete domain-scope declaration (this is conformance vector `[0]` — its real
hashes and signature appear in §9):

```json
{
  "adp_version": "1.0",
  "schema_version": 1,
  "declaration_id": "01JADP000000000000000DOMN1",
  "subject": {
    "scope": "domain",
    "domain": "example-publisher.com"
  },
  "reservations": [
    { "use": "tdm",      "actor": "any",          "status": "reserved"  },
    { "use": "ai-train", "actor": "any",          "status": "reserved"  },
    { "use": "ai-train", "actor": "search-index", "status": "permitted" }
  ],
  "declarant": {
    "id": "did:web:example-publisher.com",
    "public_key": "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=",
    "public_key_alg": "ed25519"
  },
  "authority": {
    "method": "dns-01",
    "proof": "_adp-challenge.example-publisher.com",
    "proof_digest_sha256": "d8811d214599bf1e494b8aa7187e73038941933be8295aae5269731cc8c3a686"
  },
  "effective_from": "2026-05-11T00:00:00Z",
  "issued_at": "2026-05-11T14:31:00Z",
  "supersedes": null
}
```

The **declarant signature** (§4.6) is carried *alongside* the declaration in a
proof block, not inside the canonical document — a signature cannot cover itself.

### 4.2 Versions, identifier, temporal fields

| Field | Type | Meaning |
|---|---|---|
| `adp_version` | string | Protocol version. `"1.0"` for this document. MUST be present. |
| `schema_version` | integer | Schema version. `1` for this document. MUST be present. |
| `declaration_id` | string | Globally-unique id (ULID/UUID recommended). Unique per declaration; used as the signed-message nonce, which defeats signature replay (§8.6). |
| `effective_from` | RFC 3339 UTC | Declarant-stated intent for when the reservation takes effect. Carries **no** cryptographic weight on its own — the trusted clock is the anchor (§5.3). |
| `issued_at` | RFC 3339 UTC | When the declarant issued the record. Informational. |
| `supersedes` | string or null | `declaration_id` of a prior declaration this one replaces, or `null`. The basis of revocation-as-supersession (§8.5). |

### 4.3 Subject — multiple scopes, borrowed content identifiers

The `subject` block identifies *what* the reservation covers. ADP-1 supports
three scopes, coarse to fine:

| `scope` | Keyed by | Anchored by | Typical declarant |
|---|---|---|---|
| `domain` | a `domain` string | one DNS TXT record covers everything under it | a publisher / platform |
| `creator` | a `creator` identifier + optional `collection` | a signed identity | a creator across many works |
| `work` | a `cid` array (content identifiers) | the content itself | a creator for one asset |

ADP-1 **does not invent a content identifier.** A work's `cid` is an array of
references to *existing* identifier schemes, so ADP-1 interoperates rather than
competes. A declaration MAY list several; a resolver matches on any:

```json
"subject": {
  "scope": "work",
  "cid": [
    { "type": "sha256",      "value": "b47cc0f1…ea9c4380" },
    { "type": "iscc",        "value": "ISCC:KACYPXW563EDNM" },
    { "type": "stelais-fp",  "value": "phash:dct64:9f1c2a4b8e7d6f30" }
  ]
}
```

| `cid.type` | What it is | Why it's here |
|---|---|---|
| `sha256` | Plain cryptographic hash of the asset bytes | The exact-match baseline. Anyone can compute it; no dependency. |
| `iscc` | [ISCC](https://iscc.codes), ISO 24138:2024 | The ISO-standardized content code. **It is exactly what Liccium uses** — supporting it makes ADP-1 their *complement*, not their rival. |
| `c2pa` | A [C2PA](https://c2pa.org) manifest reference (active-manifest hash / `instanceID`) | Lets a declaration point at a signed content-credential manifest. |
| `stelais-fp` | Akaeon's [Stelais](https://stelais.com) perceptual fingerprint (DCT pHash / SimHash / audio constellation) | The **robust-hash** option: survives re-encoding/cropping where `sha256` does not. |

A verifier resolving by content matches a fetched asset against any `cid` entry
whose scheme it implements; an unknown `cid.type` is skipped, never fatal.

### 4.4 Reservations — granular by use and by actor

This is where ADP-1 either interoperates or dies, and where it fixes TDMRep's
known defect. The EU consultation criticized TDMRep as *all-or-nothing*; ADP-1's
reservation is an **array** of `(use, actor, status)` triples, so a publisher
can say "no AI training, but yes to search indexing" in one record:

```json
"reservations": [
  { "use": "tdm",      "actor": "any",          "status": "reserved"  },
  { "use": "ai-train", "actor": "any",          "status": "reserved"  },
  { "use": "ai-train", "actor": "search-index", "status": "permitted" }
]
```

**`use` vocabulary (schema_version 1).** Designed to map one-to-one onto aipref
and TDMRep (§8):

| `use` | Covers |
|---|---|
| `tdm` | Text-and-data-mining generally (CDSM Art. 4 sense). |
| `ai-train` | Use as training data for an AI/ML model. |
| `ai-train-gen` | Training **generative** models specifically (lets a declarant distinguish, mirroring *Thomson Reuters v. ROSS*'s generative/non-generative line). |
| `ai-input` | Use as inference-time input / RAG retrieval. |
| `search-index` | Conventional search indexing. |

**`actor` vocabulary.** `any` (default), or a named class: `search-index`,
`research-noncommercial`, `commercial`, `no-attribution`, or a specific declared
crawler identity. Most-specific match wins; `any` is the fallback.

**`status`:** `reserved` (rights reserved — the "no/opt-out" case) or `permitted`
(use allowed, optionally under `terms` — the "yes, under these terms" case;
see §8.4).

**Resolution rule (normative).** Given a (use, actor) query, a consumer selects
the reservation whose `use` matches and whose `actor` is the most specific
match; if none matches, the reservation is **undefined** for that pair and the
consumer applies its own default policy. ADP-1 never invents a default on the
declarant's behalf.

### 4.5 Declarant identity and authority binding

A declaration is worthless unless the declarant had standing over the subject.
Two coupled blocks establish this.

**`declarant`** — who is asserting the reservation:

| Field | Meaning |
|---|---|
| `id` | A stable declarant identifier. For domain scope, a [`did:web`](https://w3c-ccg.github.io/did-method-web/) bound to the subject domain; otherwise a `key:ed25519:<label>` or other DID. MAY be pseudonymous (§8.5). |
| `public_key` | The declarant's raw 32-byte Ed25519 public key, base64. The signature (§4.6) MUST verify under this key. |
| `public_key_alg` | `"ed25519"` in schema_version 1. |

**`authority`** — *proof* that this declarant controls the subject. Without it,
anyone could declare a reservation over anyone's domain or work:

| `method` | Subject scopes | What it proves | Verifier step |
|---|---|---|---|
| `dns-01` | `domain` | Control of the domain at issuance — the `proof` names a DNS TXT location and `proof_digest_sha256` commits the challenge value, so post-hoc DNS edits are detectable. | §7 step 4: live multi-resolver TXT check (§6.1), plus `did:web` ↔ subject consistency. |
| `sig-chain` | `creator`, `work` | A chain of signatures from a key the verifier already associates with the work's authorship to the declarant key. | §7 step 4: walk the chain to a trusted anchor. |
| `c2pa` | `work` | The declarant key matches (or is chained from) the signer of the asset's C2PA manifest. | §7 step 4: verify against the manifest's certificate. |

The authority binding is what defeats forged declarations (§8.6). DNS control
proves domain authority; a signature chain proves work authorship. A declaration
that fails its authority check MUST be treated as unverified regardless of how
well-formed everything else is.

### 4.6 The declarant signature

The declarant signs a deterministic, timestamp-free **canonical message**:

```
adp:declaration:v1|<declaration_id>|<sha256(canonical_declaration_bytes)>
```

- The prefix `adp:declaration:v1` domain-separates ADP signatures from any other
  use of the key.
- `<declaration_id>` is the per-declaration nonce.
- `<sha256(canonical_declaration_bytes)>` is the lowercase hex SHA-256 of the
  canonical bytes from §4.7 — so the signature transitively covers *every* field
  of the declaration, but the signed string itself is short and reproducible.

The signature is **timestamp-free by design**: it attests to *what* the declarant
said, not *when*. Time is delegated to the anchor (§5.3). This means two
implementations always reconstruct the identical signed bytes — no clock-drift
disputes.

The signature travels in a proof block carried with (not inside) the
declaration. For conformance vector `[0]`:

```json
{
  "type": "declarant-signature",
  "alg": "ed25519",
  "canonical_message": "adp:declaration:v1|01JADP000000000000000DOMN1|b37f9b1b037df75ed8a7cc89e3c07c642960f0d1f8fe05ed5683d5c36210cd37",
  "signature": "Zx7lzKuee9nJ4ngVjCQRt5TO2LnhLioJc3oy7WCGpRoycalAF74FN9KB9Rl3NF/3Ke8tDT5neZV5k2AI06LvCA==",
  "public_key": "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA="
}
```

Ed25519 per [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): 32-byte public
keys, 64-byte signatures, deterministic (no per-signature randomness). A verifier
reconstructs the public-key object from the raw 32 bytes by prepending the
12-byte SPKI DER header `30 2a 30 05 06 03 2b 65 70 03 21 00` (or, in most
libraries, by passing the raw bytes directly).

### 4.7 Canonicalization — RFC 8785 (JCS)

If two implementations cannot reproduce the same bytes, they cannot reproduce
the same hash, and the entire verifiability claim collapses. ADP-1 therefore
pins a **deterministic canonicalization**: the
[JSON Canonicalization Scheme, RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785),
restricted to a field set that keeps JCS trivial to reproduce:

1. **Object keys sorted** by UTF-16 code unit (== codepoint order for ADP-1's
   ASCII keys), recursively at every depth.
2. **Arrays preserve order** — order is meaningful (a `merkle_proof` is
   lowest-level-first; a `reservations` list is matched most-specific-first).
3. **No insignificant whitespace.**
4. **UTF-8** output.
5. **Numbers are integers only** in canonical fields (version numbers,
   `amount_minor` in price signals). ADP-1 forbids floats in canonical fields
   precisely so implementations never reach JCS's hard number-formatting case —
   making a 10-line canonicalizer byte-exact. A verifier MUST reject a
   declaration carrying a non-integer number in a canonical field.

The canonical bytes of vector `[0]`, reproduced byte-for-byte by both reference
verifiers:

```
{"adp_version":"1.0","authority":{"method":"dns-01","proof":"_adp-challenge.example-publisher.com","proof_digest_sha256":"d8811d214599bf1e494b8aa7187e73038941933be8295aae5269731cc8c3a686"},"declarant":{"id":"did:web:example-publisher.com","public_key":"oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=","public_key_alg":"ed25519"},"declaration_id":"01JADP000000000000000DOMN1","effective_from":"2026-05-11T00:00:00Z","issued_at":"2026-05-11T14:31:00Z","reservations":[{"actor":"any","status":"reserved","use":"tdm"},{"actor":"any","status":"reserved","use":"ai-train"},{"actor":"search-index","status":"permitted","use":"ai-train"}],"schema_version":1,"subject":{"domain":"example-publisher.com","scope":"domain"},"supersedes":null}
```

`SHA-256` of those bytes is `b37f9b1b037df75ed8a7cc89e3c07c642960f0d1f8fe05ed5683d5c36210cd37` — the value the declarant signed, and the basis of the Merkle leaf (§5.1).

---

## 5. Layer two — the anchor

This is the part nobody else on the EUIPO list has. The canonical declaration
hashes to a digest; the digest is committed to **Arweave**, a public, permanent,
third-party-operated log. The anchor is what gives ADP-1 its evidentiary
property: a declaration anchored at block height *H* provably existed no later
than that block's timestamp — which is what "predates their training cutoff"
actually means in court.

### 5.1 Batch, don't anchor-per-declaration

One Arweave transaction per declaration does not survive platform scale —
that is millions of writes. ADP-1 instead **batches declarations into a Merkle
tree and anchors only the root.** Each declaration carries its **Merkle
inclusion proof**, so any single declaration is provably a member of the
anchored batch without anchoring it individually.

This is precisely the [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
design — a strong precedent to cite, because regulators already recognize CT as
*the* proven pattern for tamper-evident public logs.

**Tree construction ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)-style):**

- **Leaf hash:** `SHA-256(0x00 || canonical_declaration_bytes)`.
- **Internal node:** `SHA-256(0x01 || left || right)`.
- **Odd-count rule:** the last node at an odd-count level is **promoted
  unchanged** to the next level — *not* duplicated (CT's rule; Bitcoin
  duplicates, which admits an ambiguity attack).
- **Empty tree:** not permitted; a zero-leaf batch is never anchored.

The `0x00`/`0x01` domain-separation prefixes prevent the second-preimage attack
where a leaf is reinterpreted as an internal node.

For the two-leaf conformance batch, leaf `[0]` is
`894e2626f6c06de16cffb98915ce1d3f43722903a302f867971d3b75b3f1fc48`, leaf `[1]`
is `8dd76bd375c6e4666fddb9c7e5b869d0ccf6833dcd8044dabc3c7ff336b2a85c`, and the
root is:

```
df506c9db6a2e6b5d777aee0af0beba2704856f1df1db71f86da95b170016ca1
```

### 5.2 The anchored payload

The **only** thing written to Arweave per batch is a small payload carrying the
root (the real conformance payload):

```json
{
  "adp_version": "1.0",
  "type": "anchor-batch",
  "batch_id": "01JADP00000000000000BATCH1",
  "merkle_root_sha256": "df506c9db6a2e6b5d777aee0af0beba2704856f1df1db71f86da95b170016ca1",
  "leaf_count": 2,
  "tree_construction": "rfc6962",
  "anchor_signature": {
    "alg": "ed25519",
    "canonical_message": "adp:anchor:v1|01JADP00000000000000BATCH1|df506c9db6a2e6b5d777aee0af0beba2704856f1df1db71f86da95b170016ca1|2",
    "signature": "z7PxW5YItLb39oegsYN6+xV+wjS0peo2gcTpSQ8BtszhPT2bwRRrVn+KV2WJ3yAXZwTIZ7teTkzVba/nXSP/CA==",
    "public_key": "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc="
  }
}
```

The leaves themselves live in the operator's database and are served on demand
with each inclusion proof (§5.5 weighs the alternative). The anchor operator
signs the root so the root is bound to a published batch key, but note: **the
anchor signature is not part of the trust root** — even an unsigned root,
once on Arweave, carries the timestamp. The signature only attributes the batch.

### 5.3 What the anchor proves about time

- `effective_from` is a declarant claim. No cryptographic weight alone.
- `issued_at` is a declarant claim. Informational.
- **The trusted timestamp is the Arweave block time** of the transaction that
  anchored the batch root. It is the only timestamp no party to the declaration
  can manipulate.

A challenger arguing a declaration was backdated must argue against Arweave's
block timestamp — which requires compromising the network or forging a
transaction id that resolves to the same payload, both infeasible by the
network's design. This is the forward-only property that makes backdating
impossible (§8.6).

### 5.4 Retrieval is from Arweave, never from Akaeon

The anchored root MUST be retrievable from **any Arweave gateway or node** —
`arweave.net`, `g8way.io`, any operator's endpoint, or a self-run node — by
transaction id. It MUST NOT require an Akaeon endpoint. This is what makes
"survives the vendor" a falsifiable technical claim rather than marketing: the
verifier in §10 fetches the root with `--gateway https://arweave.net` and never
contacts an Akaeon server for the trust-bearing step.

### 5.5 Known limitation — leaf publication

Anchoring only the root makes the operator the (sole) source of inclusion
proofs. The alternative — anchoring the full leaf-hash list in the batch payload
— removes the operator as a necessary mediator at higher cost. ADP-1/1.0 anchors
roots only and treats full-leaf-list anchoring as an OPTIONAL batch mode a
verifier MAY require for high-assurance corpora. Surfaced here, not hidden.

### 5.6 Anchor substrate is swappable

Arweave is the normative default. An operator MAY dual-anchor to a second
substrate (Irys, an L1 commitment, a CA-timestamp) whose timestamps carry more
precedent weight in a given jurisdiction. Existing records remain verifiable
against their original substrate indefinitely; the choice is per-batch, never
retroactive. The verification procedure (§7) is substrate-agnostic — it needs
only "fetch the payload at this opaque id from this public log."

---

## 6. Layer three — discovery

Discovery is how a crawler or lab *finds* the declaration relevant to something
it is about to ingest. ADP-1 deliberately rides on channels existing crawlers
already read, so they trip over it without new code.

### 6.1 Domain-level discovery

A publisher with domain authority advertises a declaration three ways; a crawler
needs any one:

1. **DNS TXT record** (the one-record integration). At
   `_adp.<domain>`, a TXT record:
   ```
   _adp.example-publisher.com.  IN  TXT  "adp1; id=01JADP000000000000000DOMN1; uri=https://example-publisher.com/.well-known/adp.json"
   ```
   The same DNS zone that carries `_adp-challenge` for the `dns-01` authority
   proof (§4.5) anchors the discovery record — one zone, one authority.
   The **authority check** at verify time SHOULD query multiple independent
   resolvers (e.g. Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9) and record the
   DNSSEC chain where present, to resist resolver-level poisoning.

2. **`/.well-known/` URI.** A GET to
   `https://<domain>/.well-known/adp.json` returns the declaration plus its
   proof block and inclusion proof, per [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615).

3. **robots.txt / TDMRep extension.** A non-breaking line existing parsers
   ignore but ADP-aware ones read:
   ```
   # robots.txt
   ADP-Declaration: https://example-publisher.com/.well-known/adp.json
   ```
   and the matching TDMRep `tdm-policy` URL (§8) MAY point at the same document.

### 6.2 Work-level discovery

For a specific asset, resolution proceeds from the content identifier:

1. **Registry lookup** by `cid` — `GET /v1/lookup?cid=sha256:<hex>` (or by
   `iscc`, etc.) returns the declaration bundle.
2. **Embedded C2PA metadata** — the asset's C2PA manifest carries an ADP
   assertion (or a `cid` the registry resolves), so a C2PA-aware pipeline finds
   the declaration with no extra fetch.
3. **Hash-and-query** — hash the asset bytes (`sha256`) or compute a Stelais
   perceptual fingerprint and query the registry. The robust fingerprint matches
   even re-encoded copies, where the exact hash would miss.

Discovery is best-effort and never the trust root: however a declaration is
found, it is only believed after §7 verification.

---

## 7. The verification procedure (normative)

This is the centerpiece — the "you don't have to trust us" property expressed as
an algorithm. It is implementable in about fifty lines using only a hashing
library, an Ed25519 implementation, and an Arweave gateway URL. The
[reference verifier](#10-reference-verifier) is the literal realization; the
[test vectors](#9-conformance-test-vectors) are the conformance bar.

Given a declaration bundle (the declaration, its proof block, leaf index, tree
size, inclusion proof, claimed root, and the anchor's `arweave_tx_id`):

1. **Obtain the record.** From a `/.well-known` URI, a registry verify endpoint,
   or any mirror. Source is untrusted; the steps below establish trust.

2. **Recompute the canonical hash.** Canonicalize the declaration per §4.7 and
   compute `SHA-256`. It MUST equal the record's stated canonical hash. *(This
   is what binds every field to the signature and the leaf.)*

3. **Verify the declarant signature.** Reconstruct the canonical message
   `adp:declaration:v1|<declaration_id>|<hash>`; it MUST equal the proof block's
   `canonical_message`. Verify the Ed25519 signature under the proof's
   `public_key`, and confirm that key **equals** `declarant.public_key`. *(A
   valid signature by the wrong key proves nothing.)*

4. **Verify the declarant's authority over the subject.** Per
   `authority.method`: for `dns-01`, run the multi-resolver TXT check (§6.1) and
   confirm `did:web` consistency with the subject domain; for `sig-chain`/`c2pa`,
   walk the chain / manifest to a trusted authorship anchor. Failure here means
   *unverified*, however well-formed the rest.

5. **Fetch the anchored Merkle root from Arweave.** GET `<gateway>/<arweave_tx_id>`
   — **from an Arweave gateway, not from Akaeon.** The fetched payload's
   `merkle_root_sha256` MUST equal the record's claimed root.

6. **Verify the inclusion proof.** Run the RFC 6962 §2.1.2 verifier over
   `(leaf_hash, leaf_index, tree_size, merkle_proof)`; it MUST reconstruct the
   anchored root. Independently re-derive `leaf_hash = SHA-256(0x00 ||
   canonical_bytes)` and confirm it matches. *(`tree_size` is load-bearing —
   without it a naive verifier mis-hashes any path through a promoted node.)*

7. **Read the timestamp.** The Arweave block time of `arweave_tx_id` is the
   trusted existence-no-later-than timestamp (§5.3). Compare against the
   relevant cutoff.

A declaration is **VERIFIED** iff steps 2–6 all pass; step 7 yields the time to
reason about. If any step fails, the verifier MUST report **VERIFICATION
FAILED** and MUST NOT treat the declaration as authoritative.

### 7.1 Real output

Both reference verifiers, run offline against the shipped vectors, produce
(abridged):

```
Declaration [0] — Domain-scope opt-out, DNS authority, granular per-use/per-actor reservations.
  [PASS] 2. Canonical hash matches record — sha256=b37f9b1b037df75e…
  [PASS] 3b. Declarant signature valid
  [PASS] 3c. Signing key == declared declarant key
  [PASS] 4. Declarant authority over subject (dns-01) — did:web binds to subject domain (consistent); live DNS DEFERRED
  [PASS] 5. Anchored root == record's claimed root — root=df506c9db6a2e6b5…
  [PASS] 6. Merkle inclusion proof reconstructs anchored root
  [PASS] 6b. Leaf hash == SHA-256(0x00 || canonical bytes)
  RESULT: VERIFIED
```

Run with `--tamper`, which flips one field *after* signing, every verifier
reports **VERIFICATION FAILED** at steps 2 and 6b — proof the chain breaks
exactly where the spec says it does.

---

## 8. Cross-cutting concerns

These four sections carry most of ADP-1's strategic weight.

### 8.1 Interop mapping — the most important table in this document

ADP-1 **anchors** other protocols' declarations rather than replacing them. A
C2PA TDM assertion or a TDMRep policy can be the very payload ADP-1 makes
verifiable. This table converts every protocol on the EUIPO list from a
competitor into something ADP-1 *adds a timestamp and authority binding to* —
which is the whole reason ADP-1 does not need a slot of its own.

| ADP-1 field / value | aipref | TDMRep | robots.txt / ai.txt | C2PA |
|---|---|---|---|---|
| `reservation.status = reserved`, `use = tdm`, `actor = any` | `train-ai = n` / `tdm = n` | `tdm-reservation: 1` | `Disallow:` for the TDM agent | `c2pa.training-mining` assertion = *notAllowed* |
| `reservation.status = reserved`, `use = ai-train` | `train-ai = n` | `tdm-reservation: 1` + policy | AI-agent `Disallow:` | `cawg.training-mining` = *notAllowed* |
| `reservation.status = permitted`, `use = ai-train` | `train-ai = y` | `tdm-reservation: 0` | (allow / absent) | assertion = *allowed* |
| `reservation` per `actor` (granular) | per-agent preference | *(TDMRep has no per-actor axis — ADP-1 fixes this)* | per-user-agent block | per-assertion constraint |
| `reservation.terms` (license, price, contact) | `train-ai` + usage terms link | `tdm-policy: <url>` | (link only) | manifest `c2pa.actions` + terms |
| `subject.cid` | n/a (resource-scoped) | resource URL | path/agent | manifest `instanceID` / hash |
| `authority` (DNS / sig-chain / C2PA cert) | *(none — ADP-1 adds)* | *(none — ADP-1 adds)* | *(none)* | manifest signer cert |
| Anchor + inclusion proof + Arweave time | *(none — ADP-1 adds)* | *(none — ADP-1 adds)* | *(none)* | *(timestamp authority, optional)* |

The bottom three rows are exactly what the other protocols lack and ADP-1
supplies: a portable authority binding and a public, third-party timestamp.
**The framing is "Akaeon anchors your declaration," not "switch to Akaeon."** A
crawler already honoring aipref or TDMRep reads an ADP-1 reservation natively
via the top rows; an ADP-1 verifier adds the cryptographic assurance the others
were never designed to carry.

### 8.2 aipref / TDMRep field-level mapping

ADP-1's `(use, actor, status)` triple is built to map one-to-one onto aipref's
preference vocabulary and TDMRep's two properties:

- **TDMRep `tdm-reservation`** ⇄ a `use=tdm, actor=any` reservation: `1` ⇄
  `reserved`, `0` ⇄ `permitted`.
- **TDMRep `tdm-policy: <url>`** ⇄ `reservation.terms.license_url`.
- **aipref preferences** (the IETF AI Preferences WG vocabulary, e.g.
  `train-ai`, `search`) ⇄ the `use` axis, with aipref's per-purpose values
  mapping to `reserved`/`permitted`.

A consumer can therefore translate an ADP-1 declaration into a TDMRep header set
or an aipref response losslessly for the all-or-nothing subset, and ADP-1's
extra per-actor granularity degrades gracefully (it collapses to the `any` row
for a consumer that has no per-actor axis).

### 8.3 The reservation as a superset — opt-in licensing and RSL

ADP-1's reservation expresses not just "no" but **"yes, under these terms."** The
same rails that carry an opt-out carry the opt-out-to-opt-in licensing migration.
A `permitted` reservation MAY carry a `terms` object (this is conformance vector
`[1]`):

```json
{
  "use": "ai-train", "actor": "any", "status": "permitted",
  "terms": {
    "license": "RSL-1.0",
    "license_url": "https://example-creator.com/license",
    "price_signal": { "amount_minor": 2500, "currency": "USD", "unit": "per-work" },
    "contact": "licensing@example-creator.com"
  }
}
```

| `terms` field | Meaning |
|---|---|
| `license` | License identifier. `RSL-1.0` declares [Really Simple Licensing](https://rslstandard.org) compatibility explicitly — so the ~1,500-org RSL honor-system network becomes an **integration surface**, not a rival. |
| `license_url` | Canonical license text. Maps to TDMRep `tdm-policy`. |
| `price_signal` | A machine-readable price hint: integer `amount_minor` (forbidding floats keeps canonicalization exact, §4.7), ISO-4217 `currency`, and `unit`. |
| `contact` | How a licensee initiates. |

This is why ADP-1 is "rails," not just a registry: the day a publisher flips from
"do not train" to "train for $X," the change is one reservation `status` flip
plus a `terms` block — same format, same anchor, same verifier.

### 8.4 RSL and the honor-system networks

Declaring `license: "RSL-1.0"` does two things: it tells an RSL-aware consumer
the terms are RSL-shaped, and it lets ADP-1 *anchor* an RSL offer — adding the
authority binding and timestamp RSL's honor system lacks. ADP-1 does not replace
RSL, Spawning's `ai.txt`, or any honor-system list; it makes a member of any of
them cryptographically provable. An operator MAY ingest an existing RSL/`ai.txt`
declaration and anchor it on the declarant's behalf (with a valid authority
proof), turning a 1,500-org network into a verifiable corpus without asking any
of them to adopt a new format first.

### 8.5 Privacy and GDPR

Arweave is **permanent and public**, which collides head-on with the GDPR right
to erasure (Art. 17). ADP-1 confronts this in the format itself; it is not
optional.

- **No personal data on-chain.** A declaration MUST embed *identifiers and
  hashes*, never personal data. `subject` is a domain or a content identifier;
  `declarant.id` is a `did:web` or a key reference; `authority` is a DNS location
  and a digest. None of these are personal data, and the operator MUST reject a
  declaration that would anchor personal data in a canonical field.
- **Pseudonymous declarant keys.** A declarant MAY use a key-based identity
  (`key:ed25519:<label>`) with no link to a natural person. The authority proof
  (signature chain) establishes standing without identity. Any account-to-person
  linkage lives only in the operator's off-chain database and is erasable on
  request — the on-chain declaration contains none of it.
- **Revocation as append-only supersession.** You cannot delete from Arweave —
  ADP-1 says so plainly and turns it into the evidentiary feature it is. A
  declarant revokes by anchoring a new declaration whose `supersedes` names the
  prior `declaration_id`; a consumer resolving the subject takes the latest
  effective non-superseded declaration. The history is preserved on purpose: a
  lab that trained at T1 under a then-current reservation can still prove what
  the reservation said at T1, even after the declarant changes it at T2 > T1.

The permanence that the right-to-erasure dislikes is the same permanence that
makes the record defensible in court. ADP-1 keeps personal data off the
permanent layer so both properties hold at once.

### 8.6 Security considerations (IETF house style)

This section follows the structure expected of a [BCP 72 / RFC 3552](https://www.rfc-editor.org/rfc/rfc3552)
Security Considerations section.

- **Forged declarations** (someone declares a reservation over a subject they do
  not control) are defeated by the **authority binding** (§4.5). A forger cannot
  produce a `dns-01` proof without controlling the domain's DNS, nor a
  `sig-chain` proof without the authorship key. Verification step 4 is
  mandatory; a declaration that skips it is not verified.

- **Backdating** is made impossible by the **forward-only anchor timestamp**
  (§5.3). The declarant-stated `effective_from` carries no weight; the trusted
  time is the Arweave block time, which the network fixes at inclusion and no
  party can move earlier. The strongest a declarant can do is anchor *now*; they
  cannot anchor *in the past*.

- **Tampering after anchoring** is detected by the **canonical-hash and Merkle
  recomputation** (steps 2, 6, 6b). Any byte change alters the SHA-256, which no
  longer matches the signed message or the anchored leaf. The `--tamper`
  conformance run demonstrates the rejection.

- **Substituting a fake leaf into a real batch** fails the inclusion proof: the
  fake leaf is not in the tree, so no proof reconstructs the published root.

- **Signature replay** is defeated by the unique `declaration_id` in the signed
  message (§4.6); a replayed signature reproduces a duplicate `declaration_id`,
  which an operator rejects and a verifier can detect.

- **Second-preimage on the Merkle tree** is defeated by the `0x00`/`0x01`
  leaf/internal domain separation (§5.1), per RFC 6962.

- **DNS poisoning during the authority check** is mitigated by multi-resolver
  verification and DNSSEC-chain recording (§6.1).

- **Akaeon compromise does not break verification.** This is stated explicitly
  because it is the property the whole format rests on: verification (§7) trusts
  Akaeon for *nothing*. A compromised or malicious operator can refuse to serve
  inclusion proofs (a denial-of-service, mitigated by §5.5's optional full-leaf
  anchoring and by mirrors), or sign a fresh malicious batch (defeated because
  the *declarant* signature, not the operator, authorizes a declaration, and the
  authority binding gates it). It **cannot** retroactively alter, backdate, or
  forge any already-anchored declaration, because those are fixed by Arweave and
  the declarant's key, neither of which the operator holds.

**Residual risks ADP-1 does not solve** (stated, not hidden): a declarant who
loses control of their domain/key; a court that declines to credit blockchain
timestamps (mitigated by dual-anchoring, §5.6); and a consumer that *claims* to
have verified but did not (ADP-1 makes the honest consumer's record provable; it
cannot police a dishonest one).

---

## 9. Conformance test vectors

The vectors ship with the spec, in [`test-vectors.json`](./test-vectors.json).
They are **real**, not illustrative: real Ed25519 keypairs (from fixed test
seeds — never production keys), real JCS bytes, real SHA-256 leaf hashes, a real
RFC 6962 Merkle tree, real inclusion proofs, and a real anchored batch payload.
The generator (`gen-vectors.mjs`) is deterministic — fixed seeds, no clock, no
randomness — so anyone regenerates byte-identical output and the values below are
reproducible from scratch.

| Vector | Exercises | Canonical SHA-256 | Leaf index |
|---|---|---|---|
| `[0]` domain opt-out | `scope=domain`, `dns-01` authority, granular per-use/per-actor reservations | `b37f9b1b…6210cd37` | 0 |
| `[1]` per-work opt-in | `scope=work`, multi-`cid` (sha256 + ISCC + Stelais fp), `sig-chain` authority, RSL `terms` with price signal | `07dcef5a…15b53058` | 1 |

Shared anchor for the batch:

| Field | Value |
|---|---|
| Merkle root | `df506c9db6a2e6b5d777aee0af0beba2704856f1df1db71f86da95b170016ca1` |
| Tree size | 2 |
| Batch id | `01JADP00000000000000BATCH1` |

Between them the two vectors cover every branch of the format: both authority
methods, both `status` values, domain and work scope, all three live `cid` types,
the opt-in licensing superset, and the supersession field. A conforming
implementation MUST verify both as VERIFIED and MUST reject either when any field
is altered after signing.

---

## 10. Reference verifier

Two reference verifiers ship with the spec — the literal answer to "am I locking
into you?": you can hand an adopter code that verifies their own declaration with
Akaeon's servers switched off.

- **`verify.mjs`** — Node.js, **zero dependencies** (`node:crypto` has Ed25519
  built in).
- **`verify.py`** — Python 3, stdlib only except the `cryptography` package for
  Ed25519 (a 6-line pure-Python Ed25519 verify drops in if that dependency is
  unwanted).

Both implement §7 step-for-step, are tested against §9's vectors, and ship under
Apache-2.0. The condensed core of `verify.mjs` (the full file handles online
fetch, the authority check, and the `--tamper` self-test):

```js
import crypto from 'node:crypto'
const SPKI = Buffer.from('302a300506032b6570032100', 'hex')
const sha256 = (b) => crypto.createHash('sha256').update(b).digest()

// §4.7 — JCS canonical bytes (ADP-1 integer-only subset).
function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  return '{' + Object.keys(v).sort()
    .filter((k) => v[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
}
const ed = (pk, msg, sig) => crypto.verify(null, Buffer.from(msg, 'utf8'),
  crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pk, 'base64')]), format: 'der', type: 'spki' }),
  Buffer.from(sig, 'base64'))

// §7 step 6 — RFC 6962 §2.1.2 inclusion verifier (tree_size is load-bearing).
function inclusion(leafHex, idx, size, proof, rootHex) {
  if (idx < 0 || idx >= size || size === 0) return false
  let fn = idx, sn = size - 1, r = Buffer.from(leafHex, 'hex')
  for (const ph of proof) {
    const p = Buffer.from(ph, 'hex'); if (sn === 0) return false
    if ((fn & 1) === 1 || fn === sn) { r = sha256(Buffer.concat([Buffer.from([1]), p, r])); while ((fn & 1) === 0) { fn >>= 1; sn >>= 1 } }
    else r = sha256(Buffer.concat([Buffer.from([1]), r, p]))
    fn >>= 1; sn >>= 1
  }
  return sn === 0 && r.toString('hex') === rootHex
}

// §7 — verify one declaration bundle against an Arweave-fetched anchored root.
export function verify(rec, anchored) {
  const decl = rec.declaration, proof = rec.declarant_proof
  const bytes = Buffer.from(jcs(decl), 'utf8')
  const hash = sha256(bytes).toString('hex')
  return (
    hash === rec.canonical_declaration_sha256 &&                                   // step 2
    proof.canonical_message === `adp:declaration:v1|${decl.declaration_id}|${hash}` && // step 3a
    ed(proof.public_key, proof.canonical_message, proof.signature) &&              // step 3b
    proof.public_key === decl.declarant.public_key &&                              // step 3c
    anchored.merkle_root_sha256 === rec.merkle_root_sha256 &&                      // step 5
    inclusion(rec.leaf_hash_sha256, rec.leaf_index, rec.tree_size,                 // step 6
              rec.merkle_proof, anchored.merkle_root_sha256) &&
    sha256(Buffer.concat([Buffer.from([0]), bytes])).toString('hex') === rec.leaf_hash_sha256 // step 6b
  )
  // step 4 (authority) and step 7 (read Arweave block time) in the full file.
}
```

Run them:

```sh
node verify.mjs --vectors test-vectors.json              # offline; exits 0
node verify.mjs --vectors test-vectors.json --tamper     # proves it REJECTS forgeries
python3 verify.py --vectors test-vectors.json            # cross-language agreement
node verify.mjs --declaration-id 01J... \                # online; root from Arweave
    --registry https://api.akaeon-registry.com --gateway https://arweave.net
```

If a verifier needs an Akaeon SDK, it is no longer verifying against the public
substrate — it is verifying against Akaeon, and the trust property degrades. The
whole point is that it doesn't.

---

## 11. Governance and licensing

"Open-specified" is a claim regulators will test, and a spec with no governance
story reads as one company's private format wearing an open costume. ADP-1's
governance is therefore part of the spec, not an afterthought.

- **The specification text** (this document) is licensed **CC BY 4.0**. Anyone
  may implement, fork, or republish it with attribution.
- **The reference code and test vectors** (this repository)
  are licensed **Apache-2.0**. A successor entity can re-host verification
  without negotiating a license.
- **Change process.** Changes are proposed as numbered ADP change proposals
  against the public repository, with a public comment window. Breaking changes
  bump `adp_version`; vocabulary additions bump `schema_version` (§1.1). The
  intended end-state is to move change control to a multi-stakeholder body
  (a W3C Community Group or IETF-style process), with Akaeon as one participant
  rather than the owner.
- **Versioned, dated, reviewed.** This document is `adp_version` 1.0,
  `schema_version` 1, on a two-year review cycle. Each revision is itself a
  canonical record and is anchored on Arweave, so the spec's own version history
  is tamper-evident by the same mechanism it specifies for declarations.

---

## Appendix A — glossary

| Term | Definition |
|---|---|
| **Declaration** | The canonical record of a rights reservation (Layer 1, §4). |
| **Canonical bytes** | The RFC 8785 (JCS) UTF-8 serialization of a declaration (§4.7). The basis of its hash, signature, and Merkle leaf. |
| **Declarant** | The party asserting the reservation, identified by a key and bound to the subject by an authority proof (§4.5). |
| **Authority binding** | Cryptographic proof that the declarant controls the subject — DNS control for a domain, a signature chain for a work (§4.5). |
| **Anchor** | The commitment of a batch's Merkle root to Arweave (Layer 2, §5). |
| **Inclusion proof** | The RFC 6962 sibling-hash path proving a leaf is a member of an anchored batch (§5.1, §7 step 6). |
| **Subject** | What a declaration covers: a domain, a creator/collection, or a work keyed by a content identifier (§4.3). |
| **Reservation** | A `(use, actor, status[, terms])` triple expressing a per-use, per-actor preference (§4.4). |
| **Supersession** | Append-only revocation: a new declaration naming the `declaration_id` it replaces (§8.5). |

---

This document is versioned. Implementation framing, regulatory mapping, and the
audit-defensibility properties for one operator's deployment are in the
[Registry technical specification](https://akaeon.com/docs/spec). Integration steps are in the
[lab integration runbook](https://akaeon.com/docs/integration); a worked end-to-end scenario is in
the [concrete example](https://akaeon.com/docs/example).
