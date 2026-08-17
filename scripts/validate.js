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
const PROVENANCE = path.join(ROOT, 'src', 'hashes', 'provenance.json');

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

// The provenance record has two writers -- flux CI adds a row per published hash, the signing run
// stamps the sequence it signed at -- and a malformed edit from either would take the signer down.
// Not every hash has a row: the record starts empty against a list that predates it.
function validateProvenance() {
  if (!fs.existsSync(PROVENANCE)) {
    process.stderr.write('no provenance record yet, skipping\n');
    return null;
  }

  let record;
  try {
    record = JSON.parse(fs.readFileSync(PROVENANCE, 'utf8'));
  } catch (error) {
    check(false, `provenance record does not parse: ${error.message}`);
    return null;
  }

  if (record.signed !== undefined && record.signed !== null) {
    check(
      Number.isInteger(record.signed.seq) && record.signed.seq >= 1,
      `provenance signed.seq is not a positive integer: ${record.signed.seq}`,
    );
    check(
      typeof record.signed.issued_at === 'string' && !Number.isNaN(Date.parse(record.signed.issued_at)),
      `provenance signed.issued_at is not a parseable date: ${record.signed.issued_at}`,
    );
  }

  const rows = record.hashes || {};
  Object.entries(rows).forEach(([hash, row]) => {
    check(/^[0-9a-f]{32}$/.test(hash), `provenance row key is not a lowercase md5: ${hash}`);
    check(
      row && typeof row === 'object'
        && typeof row.published === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(row.published)
        && typeof row.commit === 'string' && /^[0-9a-f]{40}$/.test(row.commit)
        && (row.branch === null || typeof row.branch === 'string')
        && (row.tag === null || typeof row.tag === 'string'),
      `provenance row is malformed: ${hash}`,
    );
  });

  process.stderr.write(`provenance: ${Object.keys(rows).length} rows, signed seq ${record.signed ? record.signed.seq : 'none'}\n`);
  return record;
}

// The signed copy is written by CI and only exists once it has run, so its absence is not a failure
// -- unless the provenance record says a document was signed, in which case the document has gone
// missing and that must be a red run, not a skip. If it is there it must verify, it must describe
// the list beside it, and its sequence must be exactly the provenance high-water: below it is the
// restart the record exists to prevent, above it means the record missed a write.
function validateSigned(hashes, provenance) {
  const recordedSeq = provenance && provenance.signed ? provenance.signed.seq : null;

  if (!fs.existsSync(SIGNED)) {
    if (recordedSeq !== null) {
      check(false, `provenance records signed seq ${recordedSeq} but there is no signed document`);
      return;
    }
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
  check(
    typeof payload.issued_at === 'string' && !Number.isNaN(Date.parse(payload.issued_at)),
    `signed issued_at is not a parseable date: ${payload.issued_at}`,
  );

  if (recordedSeq === null) {
    check(false, `signed document at seq ${payload.seq} but the provenance record has no signed seq`);
  } else {
    check(
      payload.seq === recordedSeq,
      `signed document is at seq ${payload.seq}, provenance records ${recordedSeq}`,
    );
  }

  if (hashes) {
    const matches = payload.hashes.length === hashes.length
      && payload.hashes.every((hash, i) => hash === hashes[i]);
    check(matches, `signed document lists ${payload.hashes.length} entries, hashes.js has ${hashes.length}`);
  }

  process.stderr.write(`signed document: seq ${payload.seq}, ${payload.hashes.length} entries\n`);
}

function main() {
  const hashes = validateHashes();
  const provenance = validateProvenance();
  validateSigned(hashes, provenance);

  if (failures.length) {
    failures.forEach((failure) => process.stderr.write(`  FAIL ${failure}\n`));
    process.exit(1);
  }
  process.stderr.write('ok\n');
}

if (require.main === module) main();
