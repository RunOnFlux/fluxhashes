#!/usr/bin/env node
'use strict';

// Verifies the signed hash list against the pinned public keys, the way a consumer will.
//
// Run immediately after signing, in the same job. A signing key that has been mangled -- pasted with
// a stray newline, truncated, replaced -- produces a document that is entirely well-formed and that
// no consumer will accept. Checking here makes that a failed workflow rather than a document that
// looks published and satisfies nobody.
//
// It deliberately does not use the signing key to check its own work. It uses the published public
// keys.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Must match SIGNING.md and the set consumers pin. Any one of them verifying is enough, which is
// what lets a second key take over without updating consumers.
const PINNED_PUBLIC_KEYS = [
  '3023cb5e01dc22257ac5c31c4d12106cd0d58fa2005f867b3fdc5d303f6446ec',   // 1, CI
  'fee7b0ccf2323954af68a249eaa61f957239eb222329e08a5b6a50ced649bae8',   // 2, cold
];

function verifyDocument(document, publicKeysHex) {
  const payload = Buffer.from(document.payload_b64, 'base64');
  const signature = Buffer.from(document.sig_b64, 'base64');

  if (signature.length !== 64) {
    throw new Error(`signature is ${signature.length} bytes, expected 64`);
  }

  const accepted = publicKeysHex.some((hex) => {
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(hex, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, payload, key, signature);
  });

  if (!accepted) {
    throw new Error('signature does not verify under any pinned public key');
  }

  return JSON.parse(payload.toString('utf8'));
}

function main(argv) {
  const root = path.join(__dirname, '..');
  const document = JSON.parse(fs.readFileSync(
    argv[0] || path.join(root, 'src', 'hashes', 'hashlist-signed.json'), 'utf8',
  ));
  // eslint-disable-next-line global-require
  const hashes = require(path.join(root, 'src', 'hashes', 'hashes')).getHashes();

  const payload = verifyDocument(document, PINNED_PUBLIC_KEYS);

  // The signed bytes must be what we meant to sign, not merely something validly signed.
  if (payload.hashes.length !== hashes.length) {
    throw new Error(`signed ${payload.hashes.length} hashes, hashes.js has ${hashes.length}`);
  }
  if (!payload.hashes.every((hash, i) => hash === hashes[i])) {
    throw new Error('signed hashes do not match hashes.js');
  }

  process.stderr.write(`verified: seq ${payload.seq}, ${payload.hashes.length} hashes\n`);
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`verify-hashlist: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { verifyDocument, PINNED_PUBLIC_KEYS };
