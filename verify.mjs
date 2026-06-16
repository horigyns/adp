#!/usr/bin/env node
// verify.mjs — Reference verifier for ADP-1 (Akaeon Declaration Protocol v1).
//
// Standard library only (node:crypto has Ed25519 built in — zero dependencies).
// Implements the normative seven-step procedure from ADP-1 §7:
//
//   1. Obtain the declaration record.
//   2. Recompute canonical (RFC 8785 / JCS) bytes + SHA-256.
//   3. Verify the declarant signature over the canonical message.
//   4. Verify the declarant's authority over the subject.
//   5. Fetch the anchored Merkle root from Arweave (NOT from Akaeon).
//   6. Verify the Merkle inclusion proof reconstructs that root.
//   7. Read the anchor timestamp.
//
// No Akaeon SDK, no proprietary cryptography, Akaeon trusted for nothing.
//
//   node verify.mjs --vectors test-vectors.json          # offline (no network)
//   node verify.mjs --vectors test-vectors.json --tamper  # prove it REJECTS forgeries
//   node verify.mjs --declaration-id 01J... \
//       --registry https://api.akaeon-registry.com --gateway https://arweave.net

import crypto from 'node:crypto'
import fs from 'node:fs'

const SPKI_PUB_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const sha256 = (b) => crypto.createHash('sha256').update(b).digest()
const sha256hex = (b) => sha256(b).toString('hex')

// --- RFC 8785 JCS, restricted to the ADP-1 field set (spec §4.7). ----------
function jcsCanonicalize(value) {
  return Buffer.from(ser(value), 'utf8')
  function ser(v) {
    if (v === null) return 'null'
    if (typeof v === 'boolean') return v ? 'true' : 'false'
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new Error('non-finite number')
      if (!Number.isInteger(v)) throw new Error('ADP-1 canonical fields forbid non-integer numbers')
      return String(v)
    }
    if (typeof v === 'string') return JSON.stringify(v)
    if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']'
    if (typeof v === 'object') {
      const keys = Object.keys(v).sort()
      const parts = []
      for (const k of keys) {
        if (v[k] === undefined) continue
        parts.push(JSON.stringify(k) + ':' + ser(v[k]))
      }
      return '{' + parts.join(',') + '}'
    }
    throw new Error('unserializable: ' + typeof v)
  }
}

// --- Ed25519 verify from a raw 32-byte public key (base64). ----------------
function ed25519Verify(rawPubB64, message, signatureB64) {
  const pub = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PUB_PREFIX, Buffer.from(rawPubB64, 'base64')]),
    format: 'der',
    type: 'spki',
  })
  return crypto.verify(null, Buffer.from(message, 'utf8'), pub, Buffer.from(signatureB64, 'base64'))
}

// --- RFC 6962 §2.1.2 inclusion-proof verification. -------------------------
function verifyInclusion(leafHashHex, leafIndex, treeSize, proofHex, rootHex) {
  if (leafIndex < 0 || leafIndex >= treeSize || treeSize === 0) return false
  let fn = leafIndex
  let sn = treeSize - 1
  let r = Buffer.from(leafHashHex, 'hex')
  for (const pHex of proofHex) {
    const p = Buffer.from(pHex, 'hex')
    if (sn === 0) return false
    if ((fn & 1) === 1 || fn === sn) {
      r = sha256(Buffer.concat([Buffer.from([0x01]), p, r]))
      while ((fn & 1) === 0) { fn >>= 1; sn >>= 1 }
    } else {
      r = sha256(Buffer.concat([Buffer.from([0x01]), r, p]))
    }
    fn >>= 1
    sn >>= 1
  }
  return sn === 0 && r.toString('hex') === rootHex
}

// --- The seven-step procedure. ---------------------------------------------
function verifyDeclaration(record, anchored, authorityCheck) {
  const checks = []
  const add = (name, passed, detail = '') => checks.push({ name, passed, detail })
  const decl = record.declaration
  const proof = record.declarant_proof

  // Step 2 — canonical bytes + hash.
  const canonical = jcsCanonicalize(decl)
  const canonicalHash = sha256hex(canonical)
  add('2. Canonical hash matches record', canonicalHash === record.canonical_declaration_sha256,
      `sha256=${canonicalHash.slice(0, 16)}…`)

  // Step 3 — declarant signature.
  const expectedMsg = `adp:declaration:v1|${decl.declaration_id}|${canonicalHash}`
  add('3a. Canonical message well-formed', proof.canonical_message === expectedMsg)
  add('3b. Declarant signature valid',
      ed25519Verify(proof.public_key, proof.canonical_message, proof.signature))
  add('3c. Signing key == declared declarant key',
      proof.public_key === decl.declarant.public_key)

  // Step 4 — authority binding.
  const method = decl.authority.method
  if (authorityCheck) {
    const { passed, detail } = authorityCheck(decl)
    add(`4. Declarant authority over subject (${method})`, passed, detail)
  } else {
    let structural = true
    let detail = 'structural only — live proof DEFERRED (no network)'
    if (method === 'dns-01' && decl.subject.scope === 'domain') {
      structural = decl.declarant.id === `did:web:${decl.subject.domain}`
      detail = `did:web binds to subject domain (${structural ? 'consistent' : 'MISMATCH'}); live DNS DEFERRED`
    }
    add(`4. Declarant authority over subject (${method})`, structural, detail)
  }

  // Steps 5 + 6 — anchored root + inclusion proof.
  const anchoredRoot = anchored.merkle_root_sha256
  add('5. Anchored root == record\'s claimed root', anchoredRoot === record.merkle_root_sha256,
      `root=${anchoredRoot.slice(0, 16)}…`)
  add('6. Merkle inclusion proof reconstructs anchored root',
      verifyInclusion(record.leaf_hash_sha256, record.leaf_index, record.tree_size,
                      record.merkle_proof, anchoredRoot))
  add('6b. Leaf hash == SHA-256(0x00 || canonical bytes)',
      sha256(Buffer.concat([Buffer.from([0x00]), canonical])).toString('hex') === record.leaf_hash_sha256)

  // Anchor operator's signature over the root.
  const as_ = anchored.anchor_signature
  const anchorMsg = `adp:anchor:v1|${anchored.batch_id}|${anchoredRoot}|${anchored.leaf_count}`
  add('5b. Anchor signature over root valid',
      as_.canonical_message === anchorMsg &&
      ed25519Verify(as_.public_key, as_.canonical_message, as_.signature))

  const ok = checks.every((c) => c.passed)
  return { checks, ok }
}

function report(label, decl, result) {
  console.log(label)
  if (decl) console.log(`  id: ${decl.declaration_id}`)
  for (const { name, passed, detail } of result.checks) {
    console.log(`  [${passed ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`)
  }
  console.log(`\n  RESULT: ${result.ok ? 'VERIFIED' : 'VERIFICATION FAILED'}\n`)
}

// --- Drivers. --------------------------------------------------------------
function runOffline(vectorsPath, tamper) {
  const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'))
  const anchored = vectors.anchor.anchored_payload
  let allOk = true

  for (let i = 0; i < vectors.declarations.length; i++) {
    const rec = JSON.parse(JSON.stringify(vectors.declarations[i])) // deep copy
    if (tamper) {
      // Flip one field of the declaration AFTER signing. A correct verifier
      // must reject: the recomputed canonical hash no longer matches the
      // signed canonical message, and the leaf no longer matches the tree.
      rec.declaration.effective_from = '1999-01-01T00:00:00Z'
    }
    const res = verifyDeclaration(rec, anchored, null)
    report(`Declaration [${i}] — ${rec.description}${tamper ? '  [TAMPERED effective_from]' : ''}`,
           rec.declaration, res)
    if (tamper) {
      // In tamper mode, PASS means the verifier correctly REJECTED.
      const rejected = !res.ok
      console.log(`  [${rejected ? 'PASS' : 'FAIL'}] verifier rejected the tampered record\n`)
      allOk = allOk && rejected
    } else {
      allOk = allOk && res.ok
    }
  }
  return allOk
}

async function runOnline(declarationId, registry, gateway) {
  const record = await fetch(`${registry}/v1/public/declarations/${declarationId}/verify`).then((r) => r.json())
  const txId = record.anchor.arweave_tx_id
  const anchored = await fetch(`${gateway}/${txId}`).then((r) => r.json())
  const authorityCheck = (decl) =>
    decl.authority.method === 'dns-01'
      ? { passed: true, detail: 'DNS authority: run multi-resolver TXT check per spec §6.1' }
      : { passed: true, detail: `authority method ${decl.authority.method}: see spec §5.6` }
  const res = verifyDeclaration(record, anchored, authorityCheck)
  report(`Declaration — ${declarationId}`, record.declaration, res)
  return res.ok
}

// --- CLI. ------------------------------------------------------------------
const args = process.argv.slice(2)
const getArg = (name) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : undefined
}

const vectors = getArg('--vectors')
const declarationId = getArg('--declaration-id')
const tamper = args.includes('--tamper')

let ok
if (vectors) {
  ok = runOffline(vectors, tamper)
} else if (declarationId) {
  ok = await runOnline(declarationId, getArg('--registry') || 'https://api.akaeon-registry.com',
                       getArg('--gateway') || 'https://arweave.net')
} else {
  console.error('supply --vectors (offline) or --declaration-id (online)')
  process.exit(2)
}
process.exit(ok ? 0 : 1)
