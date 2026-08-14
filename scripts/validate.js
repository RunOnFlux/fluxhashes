#!/usr/bin/env node

// Shape-checks what this repository publishes.
//
// The list is served by requiring it, so a file that does not load takes the endpoint down rather
// than merely publishing something odd. Flux CI checks its own edit before pushing, but the list is
// also edited by hand -- a cull removes entries in bulk -- and that path had nothing in front of it.
//
// This checks shape only. Whether a particular hash *should* be listed is not knowable from here:
// removing one that is still in use looks identical to removing one that is obsolete.

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SIGNED = path.join(ROOT, 'src', 'hashes', 'hashlist-signed.json');

const failures = [];

function check(condition, message) {
  if (!condition) failures.push(message);
}

function validateHashes() {
  // eslint-disable-next-line global-require
  const hashes = require('../src/hashes/hashes').getHashes();

  check(Array.isArray(hashes), 'hashes.js did not return an array');
  if (!Array.isArray(hashes)) return null;

  check(hashes.length > 0, 'the list is empty');

  const malformed = hashes.filter((hash) => typeof hash !== 'string' || !/^[0-9a-f]{32}$/.test(hash));
  check(malformed.length === 0, `${malformed.length} entries are not lowercase md5s: ${malformed.slice(0, 3)}`);

  // Harmless to serve, but a sign that an edit went in twice, which is worth seeing.
  const duplicates = hashes.filter((hash, i) => hashes.indexOf(hash) !== i);
  check(duplicates.length === 0, `${duplicates.length} duplicate entries: ${[...new Set(duplicates)].slice(0, 3)}`);

  process.stderr.write(`hashes.js: ${hashes.length} entries\n`);
  return hashes;
}

// The signed copy is written by CI and only exists once it has run, so its absence is not a failure.
// If it is there it must verify, and it must describe the list beside it -- a signed document that
// no longer matches what it claims to sign would be accepted by a consumer and then not contain
// what that consumer is looking for.
function validateSigned(hashes) {
  if (!fs.existsSync(SIGNED)) {
    process.stderr.write('no signed document yet, skipping\n');
    return;
  }

  // eslint-disable-next-line global-require
  const { verifyDocument, PINNED_PUBLIC_KEYS } = require('./verify-hashlist');

  let payload;
  try {
    payload = verifyDocument(JSON.parse(fs.readFileSync(SIGNED, 'utf8')), PINNED_PUBLIC_KEYS);
  } catch (error) {
    check(false, `signed document does not verify: ${error.message}`);
    return;
  }

  check(Number.isInteger(payload.seq) && payload.seq >= 1, `signed sequence is not a positive integer: ${payload.seq}`);

  if (hashes) {
    const matches = payload.hashes.length === hashes.length
      && payload.hashes.every((hash, i) => hash === hashes[i]);
    check(matches, `signed document lists ${payload.hashes.length} entries, hashes.js has ${hashes.length}`);
  }

  process.stderr.write(`signed document: seq ${payload.seq}, ${payload.hashes.length} entries\n`);
}

function main() {
  const hashes = validateHashes();
  validateSigned(hashes);

  if (failures.length) {
    failures.forEach((failure) => process.stderr.write(`  FAIL ${failure}\n`));
    process.exit(1);
  }
  process.stderr.write('ok\n');
}

if (require.main === module) main();
