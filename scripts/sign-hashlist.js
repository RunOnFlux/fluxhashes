#!/usr/bin/env node
'use strict';

// Signs the hash list this repository publishes, so consumers can verify it came from us rather
// than trusting the transport or whatever relayed it.
//
// The signed document sits alongside the unsigned array rather than replacing it; both are served.
//
// The payload is signed and transmitted as exact bytes in base64, so verification never depends on
// the signer and the verifier agreeing about JSON key order or whitespace -- the kind of agreement
// that holds in testing and fails in production.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUTPUT = path.join(ROOT, 'src', 'hashes', 'hashlist-signed.json');

// A raw 32-byte Ed25519 seed is not directly importable; Node wants PKCS8. The prefix is fixed for
// the algorithm, so prepending it is enough.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX_LENGTH = 12;

function privateKeyFromSeed(seedB64) {
  const seed = Buffer.from(seedB64, 'base64');
  if (seed.length !== 32) {
    throw new Error(`signing seed must be 32 bytes, got ${seed.length}`);
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

// The raw 32 bytes consumers pin, rather than any DER wrapping around them.
function rawPublicKey(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return spki.subarray(SPKI_ED25519_PREFIX_LENGTH);
}

function buildSignedDocument(seq, hashes, privateKey) {
  if (!Number.isInteger(seq) || seq < 1) {
    throw new Error('seq must be a positive integer');
  }
  if (!Array.isArray(hashes) || hashes.length === 0) {
    throw new Error('hashes must be a non-empty array');
  }
  if (!hashes.every((h) => typeof h === 'string' && /^[0-9a-f]{32}$/.test(h))) {
    throw new Error('every hash must be a lowercase 32-character md5');
  }

  const payload = Buffer.from(JSON.stringify({ seq, hashes }), 'utf8');
  const signature = crypto.sign(null, payload, privateKey);

  return {
    payload_b64: payload.toString('base64'),
    sig_b64: signature.toString('base64'),
  };
}

// The sequence lives in the published document rather than in a file beside it, so there is nothing
// to drift out of step with what was actually signed. A consumer refuses a document whose sequence
// is below the highest it has accepted, so an older validly-signed list cannot be replayed over a
// newer one.
function previousDocument() {
  if (!fs.existsSync(OUTPUT)) {
    return null;
  }
  const document = JSON.parse(fs.readFileSync(OUTPUT, 'utf8'));
  return JSON.parse(Buffer.from(document.payload_b64, 'base64').toString('utf8'));
}

function main() {
  const seedB64 = process.env.HASHLIST_SIGNING_SEED_B64;
  if (!seedB64) {
    throw new Error('HASHLIST_SIGNING_SEED_B64 is not set');
  }

  // eslint-disable-next-line global-require
  const hashes = require(path.join(ROOT, 'src', 'hashes', 'hashes')).getHashes();
  const previous = previousDocument();

  // Re-signing an unchanged list would burn a sequence for nothing, and every node would have to
  // fetch and verify a document identical to the one it already holds.
  if (previous
      && previous.hashes.length === hashes.length
      && previous.hashes.every((hash, i) => hash === hashes[i])) {
    process.stderr.write(`unchanged at seq ${previous.seq}, nothing to sign\n`);
    process.stdout.write('changed=false\n');
    return;
  }

  const seq = previous ? previous.seq + 1 : 1;
  const privateKey = privateKeyFromSeed(seedB64);
  const document = buildSignedDocument(seq, hashes, privateKey);

  fs.writeFileSync(OUTPUT, `${JSON.stringify(document, null, 2)}\n`);
  process.stderr.write(`signed seq ${seq} over ${hashes.length} hashes\n`);
  process.stderr.write(`public key (raw, hex): ${rawPublicKey(privateKey).toString('hex')}\n`);
  process.stdout.write('changed=true\n');
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`sign-hashlist: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { privateKeyFromSeed, rawPublicKey, buildSignedDocument };
