#!/usr/bin/env node
// gen-vectors.mjs — Test-vector generator for ADP-1 (Akaeon Declaration Protocol v1).
//
// Produces REAL cryptographic test vectors: deterministic Ed25519 keypairs
// (seeded from a fixed 32-byte seed so the output is byte-stable across runs
// and machines), JCS-canonicalized declaration bytes (RFC 8785), SHA-256 leaf
// hashes, an RFC 6962 Merkle tree, inclusion proofs, and a declarant signature
// over the canonical bytes of each declaration.
//
// The output (test-vectors.json) is the ground truth the reference verifiers
// (verify.py, verify.mjs) are tested against, and the source of every concrete
// hash/signature/proof value quoted in the ADP-1 specification. Regenerating
// must be deterministic: same seeds in, byte-identical vectors out. No Date.now,
// no randomness — every key is derived from a fixed seed.
//
//   node gen-vectors.mjs           # writes ./test-vectors.json
//   node gen-vectors.mjs --check   # regenerate in-memory, diff against the file
//
// Standard library only. No Akaeon code. The whole point is that this is
// reproducible by anyone.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const OUT = path.join(__dirname, 'test-vectors.json')

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest()
const hex = (buf) => buf.toString('hex')
const b64 = (buf) => buf.toString('base64')

// Ed25519 SPKI/PKCS8 DER prefixes — let us build a key object from a raw
// 32-byte seed (PKCS8) and emit/import a raw 32-byte public key (SPKI),
// using only node:crypto. This is the same trick the standalone verifier uses.
const PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PUB_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

/** Build a deterministic Ed25519 keypair from a fixed 32-byte seed. */
function keypairFromSeed(seed32) {
  if (seed32.length !== 32) throw new Error('seed must be 32 bytes')
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_SEED_PREFIX, seed32]),
    format: 'der',
    type: 'pkcs8',
  })
  const publicKey = crypto.createPublicKey(privateKey)
  const spki = publicKey.export({ format: 'der', type: 'spki' })
  const rawPub = spki.subarray(spki.length - 32) // last 32 bytes are the raw key
  return { privateKey, publicKey, rawPub }
}

/** Ed25519 signature (raw 64 bytes) over a UTF-8 message string. */
function sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey)
}

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme (JCS).
// ---------------------------------------------------------------------------
// We implement the subset of JCS that ADP-1 declarations exercise:
//   - object keys sorted by UTF-16 code unit (the JS default sort, which
//     matches JCS for the BMP-only ASCII keys ADP-1 uses);
//   - arrays preserve order;
//   - strings escaped per the JSON grammar with the minimal escape set;
//   - numbers: ADP-1 declarations use only integers in the small range
//     (version numbers, prices in minor units), which JSON.stringify emits
//     identically to ECMAScript Number::toString / JCS. ADP-1 forbids floats
//     in canonical fields precisely so we never hit the hard part of JCS.
// For ADP-1's field set this is byte-identical to a full JCS implementation;
// the spec's §4.7 pins the exact constraints that keep it so.
function jcsCanonicalize(value) {
  return Buffer.from(serialize(value), 'utf8')

  function serialize(v) {
    if (v === null) return 'null'
    if (typeof v === 'boolean') return v ? 'true' : 'false'
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new Error('non-finite number not allowed')
      if (!Number.isInteger(v)) throw new Error('ADP-1 canonical fields forbid non-integer numbers')
      return String(v)
    }
    if (typeof v === 'string') return JSON.stringify(v) // JSON.stringify matches JCS string escaping for ADP-1 strings
    if (Array.isArray(v)) return '[' + v.map(serialize).join(',') + ']'
    if (typeof v === 'object') {
      const keys = Object.keys(v).sort() // UTF-16 code-unit order; ASCII keys → JCS order
      const parts = []
      for (const k of keys) {
        if (v[k] === undefined) continue
        parts.push(JSON.stringify(k) + ':' + serialize(v[k]))
      }
      return '{' + parts.join(',') + '}'
    }
    throw new Error('unserializable value: ' + typeof v)
  }
}

// ---------------------------------------------------------------------------
// RFC 6962-style Merkle tree (leaf 0x00, internal 0x01, odd-count promotion).
// ---------------------------------------------------------------------------

const LEAF = Buffer.from([0x00])
const NODE = Buffer.from([0x01])
const leafHash = (canonicalBytes) => sha256(Buffer.concat([LEAF, canonicalBytes]))
const nodeHash = (l, r) => sha256(Buffer.concat([NODE, l, r]))

function buildTree(leaves) {
  if (leaves.length === 0) throw new Error('empty tree not permitted')
  const levels = [leaves.slice()]
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1]
    const next = []
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 < cur.length) next.push(nodeHash(cur[i], cur[i + 1]))
      else next.push(cur[i]) // promote unchanged
    }
    levels.push(next)
  }
  return { levels, root: levels[levels.length - 1][0], leafCount: leaves.length }
}

function inclusionProof(tree, leafIndex) {
  const proof = []
  let index = leafIndex
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const cur = tree.levels[level]
    const isLeft = (index & 1) === 0
    const sib = isLeft ? index + 1 : index - 1
    if (sib < cur.length) proof.push(hex(cur[sib]))
    index >>= 1
  }
  return proof
}

// ---------------------------------------------------------------------------
// Fixed inputs (no randomness, no clock).
// ---------------------------------------------------------------------------

// Deterministic seeds. These are test seeds — NEVER used in production.
const REGISTRY_SEED = Buffer.alloc(32, 0x11) // 0x1111... — the anchor operator's batch key
const DECLARANT_A_SEED = Buffer.alloc(32, 0x22) // domain-scope declarant
const DECLARANT_B_SEED = Buffer.alloc(32, 0x33) // per-work declarant (signature-chain authority)

const registry = keypairFromSeed(REGISTRY_SEED)
const declA = keypairFromSeed(DECLARANT_A_SEED)
const declB = keypairFromSeed(DECLARANT_B_SEED)

// A fixed asset for the per-work declaration: the bytes of the string below.
// Its plain SHA-256 is the content identifier (cid "sha256:...").
const ASSET_BYTES = Buffer.from('The quick brown fox jumps over the lazy dog.\n', 'utf8')
const ASSET_SHA256 = hex(sha256(ASSET_BYTES))

const PREFIX_DECL = 'adp:declaration:v1'
const PREFIX_BATCH = 'adp:anchor:v1'

// ---------------------------------------------------------------------------
// Declaration 1 — domain scope, DNS authority, opt-out (no-training).
// ---------------------------------------------------------------------------

const decl1 = {
  adp_version: '1.0',
  schema_version: 1,
  declaration_id: '01JADP000000000000000DOMN1',
  subject: {
    scope: 'domain',
    domain: 'example-publisher.com',
  },
  reservations: [
    { use: 'tdm', actor: 'any', status: 'reserved' },
    { use: 'ai-train', actor: 'any', status: 'reserved' },
    { use: 'ai-train', actor: 'search-index', status: 'permitted' },
  ],
  declarant: {
    id: 'did:web:example-publisher.com',
    public_key: b64(declA.rawPub),
    public_key_alg: 'ed25519',
  },
  authority: {
    method: 'dns-01',
    proof: '_adp-challenge.example-publisher.com',
    proof_digest_sha256: hex(sha256(Buffer.from('adp-domain-control-token-DOMN1', 'utf8'))),
  },
  effective_from: '2026-05-11T00:00:00Z',
  issued_at: '2026-05-11T14:31:00Z',
  supersedes: null,
}

// ---------------------------------------------------------------------------
// Declaration 2 — per-work scope, content-id subject, signature-chain
// authority, opt-IN (licensing offer). Exercises the superset.
// ---------------------------------------------------------------------------

const decl2 = {
  adp_version: '1.0',
  schema_version: 1,
  declaration_id: '01JADP000000000000000WORK2',
  subject: {
    scope: 'work',
    cid: [
      { type: 'sha256', value: ASSET_SHA256 },
      { type: 'iscc', value: 'ISCC:KACYPXW563EDNM' },
      { type: 'stelais-fp', value: 'phash:dct64:9f1c2a4b8e7d6f30' },
    ],
  },
  reservations: [
    { use: 'ai-train', actor: 'any', status: 'permitted', terms: {
      license: 'RSL-1.0',
      license_url: 'https://example-creator.com/license',
      price_signal: { amount_minor: 2500, currency: 'USD', unit: 'per-work' },
      contact: 'licensing@example-creator.com',
    } },
    { use: 'ai-train', actor: 'no-attribution', status: 'reserved' },
  ],
  declarant: {
    id: 'key:ed25519:declarant-b',
    public_key: b64(declB.rawPub),
    public_key_alg: 'ed25519',
  },
  authority: {
    method: 'sig-chain',
    proof: 'self-asserted-authorship',
  },
  effective_from: '2026-05-11T00:00:00Z',
  issued_at: '2026-05-11T14:32:10Z',
  supersedes: null,
}

// ---------------------------------------------------------------------------
// Sign each declaration. The declarant signs the canonical message:
//   adp:declaration:v1|<declaration_id>|<sha256(canonical_declaration_bytes)>
// The canonical declaration bytes are the JCS bytes of the declaration object
// WITHOUT the `proof` block (the signature can't cover itself). The verifier
// recomputes these exact bytes.
// ---------------------------------------------------------------------------

function signDeclaration(decl, declarantKeypair) {
  const canonicalBytes = jcsCanonicalize(decl)
  const declHash = hex(sha256(canonicalBytes))
  const canonicalMessage = `${PREFIX_DECL}|${decl.declaration_id}|${declHash}`
  const signature = sign(declarantKeypair.privateKey, canonicalMessage)
  return {
    canonical_bytes_utf8: canonicalBytes.toString('utf8'),
    canonical_sha256: declHash,
    proof_block: {
      type: 'declarant-signature',
      alg: 'ed25519',
      canonical_message: canonicalMessage,
      signature: b64(signature),
      public_key: b64(declarantKeypair.rawPub),
    },
  }
}

const signed1 = signDeclaration(decl1, declA)
const signed2 = signDeclaration(decl2, declB)

// ---------------------------------------------------------------------------
// Layer 2 — batch the two declarations into a Merkle tree, anchor the root.
// The leaf is SHA-256(0x00 || canonical_declaration_bytes).
// ---------------------------------------------------------------------------

const leaf1 = leafHash(jcsCanonicalize(decl1))
const leaf2 = leafHash(jcsCanonicalize(decl2))
const tree = buildTree([leaf1, leaf2])
const rootHex = hex(tree.root)

// The anchored batch payload — exactly what is written to Arweave (one tx per
// batch). The anchor operator signs the root with its batch key.
const batchCanonicalMessage = `${PREFIX_BATCH}|01JADP00000000000000BATCH1|${rootHex}|2`
const batchSig = sign(registry.privateKey, batchCanonicalMessage)

const anchoredPayload = {
  adp_version: '1.0',
  type: 'anchor-batch',
  batch_id: '01JADP00000000000000BATCH1',
  merkle_root_sha256: rootHex,
  leaf_count: 2,
  tree_construction: 'rfc6962',
  anchor_signature: {
    alg: 'ed25519',
    canonical_message: batchCanonicalMessage,
    signature: b64(batchSig),
    public_key: b64(registry.rawPub),
  },
}

// A simulated Arweave transaction id: the Arweave tx id is the base64url
// SHA-256 of the (signed) tx; we don't sign a real Arweave tx here, but we
// DO bind the test vector to the anchored payload by deriving a stable
// identifier from its canonical bytes. The reference verifiers treat
// `arweave_tx_id` as opaque and fetch `arweave_url` for the payload; in the
// offline test harness they read the payload below directly.
const anchoredCanonical = jcsCanonicalize(anchoredPayload)
const fauxTxId = crypto.createHash('sha256').update(anchoredCanonical).digest('base64url')

// ---------------------------------------------------------------------------
// Assemble the vectors.
// ---------------------------------------------------------------------------

function vector(decl, signed, leaf, index) {
  return {
    description:
      decl.subject.scope === 'domain'
        ? 'Domain-scope opt-out, DNS authority, granular per-use/per-actor reservations.'
        : 'Per-work opt-in licensing offer, content-id subject, signature-chain authority.',
    declaration: decl,
    canonical_declaration_utf8: signed.canonical_bytes_utf8,
    canonical_declaration_sha256: signed.canonical_sha256,
    declarant_proof: signed.proof_block,
    leaf_hash_sha256: hex(leaf),
    leaf_index: index,
    tree_size: 2,
    merkle_proof: inclusionProof(tree, index),
    merkle_root_sha256: rootHex,
  }
}

const vectors = {
  spec: 'ADP-1 (Akaeon Declaration Protocol, version 1.0)',
  generated_by: 'spec/adp-1/gen-vectors.mjs (deterministic — fixed seeds, no clock, no randomness)',
  note:
    'All keys are derived from fixed test seeds (0x11.., 0x22.., 0x33..) and MUST NOT be used in production. ' +
    'Regenerating with the same generator yields byte-identical output.',
  asset_for_work_vector: {
    bytes_utf8: ASSET_BYTES.toString('utf8'),
    sha256: ASSET_SHA256,
  },
  anchor: {
    arweave_tx_id: fauxTxId,
    arweave_url: `https://arweave.net/${fauxTxId}`,
    note:
      'In production arweave_tx_id is a real Arweave transaction id and arweave_url returns the anchored_payload below. ' +
      'The offline test harness reads anchored_payload directly so the verifiers run with no network.',
    anchored_payload: anchoredPayload,
  },
  declarations: [
    vector(decl1, signed1, leaf1, 0),
    vector(decl2, signed2, leaf2, 1),
  ],
}

// ---------------------------------------------------------------------------
// Emit or check.
// ---------------------------------------------------------------------------

const serialized = JSON.stringify(vectors, null, 2) + '\n'

if (process.argv.includes('--check')) {
  const existing = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : ''
  if (existing === serialized) {
    console.log('test-vectors.json is up to date (byte-identical).')
    process.exit(0)
  } else {
    console.error('test-vectors.json is STALE — re-run `node gen-vectors.mjs` to regenerate.')
    process.exit(1)
  }
}

fs.writeFileSync(OUT, serialized)
console.log(`Wrote ${OUT}`)
console.log(`  merkle_root:   ${rootHex}`)
console.log(`  decl[0] hash:  ${signed1.canonical_sha256}`)
console.log(`  decl[1] hash:  ${signed2.canonical_sha256}`)
console.log(`  arweave_tx:    ${fauxTxId}`)
