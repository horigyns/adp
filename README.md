# ADP-1 — the Akaeon Declaration Protocol

An **open, vendor-independent format** for machine-readable rights reservations
against AI training and text-and-data-mining (TDM). A third party can verify any
ADP-1 declaration **without trusting Akaeon at all** — using only a hashing
library, an Ed25519 implementation, and a public Arweave gateway URL.

This repository is the open standard. It depends on no Akaeon code, service, or
account. If every Akaeon server is gone, everything here still verifies any
declaration that was ever anchored.

- **[`SPEC.md`](./SPEC.md)** — the normative specification (ADP-1, `adp_version`
  1.0, `schema_version` 1). Three layers — declaration, anchor, discovery — a
  normative seven-step verification procedure, and cross-cutting sections on
  interop (aipref / TDMRep / robots.txt / C2PA), opt-in licensing + RSL,
  privacy/GDPR, and security.
- **[`verify.mjs`](./verify.mjs)** — reference verifier, Node.js, zero
  dependencies (`node:crypto` has Ed25519 built in).
- **[`verify.py`](./verify.py)** — reference verifier, Python 3 (stdlib +
  `cryptography` for Ed25519).
- **[`test-vectors.json`](./test-vectors.json)** — canonical conformance
  vectors: real Ed25519 keys, JCS canonical bytes, a real RFC 6962 Merkle tree,
  inclusion proofs, and an anchored batch payload. The source of every concrete
  hash/signature quoted in the spec.
- **[`gen-vectors.mjs`](./gen-vectors.mjs)** — deterministic generator for the
  vectors (fixed seeds, no clock, no randomness → byte-identical output).

## Why this is its own thing

ADP-1 is the *format and the proof*, not the *system*. The Akaeon Registry is
one operator that implements ADP-1 — its batcher, DNS-challenge flow, API, and
key custody are a separate, proprietary concern. You can implement ADP-1
end-to-end, verify any declaration, and build a competing registry from this
repository alone. That separability is the point: adopters are not locking into
a private dependency.

## Verify in 30 seconds (offline, no network)

```sh
# Node — zero dependencies
node verify.mjs --vectors test-vectors.json

# Python — pip install cryptography
python3 verify.py --vectors test-vectors.json
```

Each prints a PASS line for the seven normative checks and exits `0`.

### Prove the verifier rejects forgeries

A verifier that always says PASS is worthless. `--tamper` flips one field of
each declaration *after* it was signed; a correct verifier must reject it:

```sh
node verify.mjs --vectors test-vectors.json --tamper
```

### Verify a live declaration (root fetched from Arweave, not from Akaeon)

```sh
node verify.mjs --declaration-id 01J... \
    --registry https://api.akaeon-registry.com \
    --gateway https://arweave.net
```

`--gateway` can be any Arweave node, a mirror, or your own — the trust-bearing
fetch never touches an Akaeon server.

### Regenerate / CI-check the vectors

```sh
node gen-vectors.mjs           # rewrite test-vectors.json
node gen-vectors.mjs --check   # fail if stale
```

## Licensing

Open-specified is a claim that should survive inspection, so the licensing is
split and explicit:

| What | License | File |
|------|---------|------|
| Specification text (`SPEC.md`) | **CC BY 4.0** | [`LICENSE-SPEC.txt`](./LICENSE-SPEC.txt) |
| Reference code + test vectors | **Apache-2.0** | [`LICENSE-CODE.txt`](./LICENSE-CODE.txt) |

A successor entity can re-host verification without negotiating a license.

## Governance

Changes are proposed as numbered ADP change proposals against this repository
with a public comment window. Breaking changes bump `adp_version`; vocabulary
additions bump `schema_version`. The intended end-state is to move change
control to a multi-stakeholder body (a W3C Community Group or IETF-style
process), with Akaeon as one participant rather than the owner. See `SPEC.md`
§11.

---

A rendered copy of the specification is published at
<https://akaeon.com/docs/declaration-format>. The Akaeon Registry's
operator-specific technical specification (regulatory mapping, audit
defensibility, deployment) is published separately at
<https://akaeon.com/docs/spec> and is **not** part of this open standard.
