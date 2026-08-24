#!/usr/bin/env node

// Shape-checks what this repository publishes.
//
// The list is served by requiring it, so a file that does not load takes the endpoint down rather
// than merely publishing something odd. The three outputs have one writer -- the signer, which
// runs this as a self-check before pushing -- so no legitimate commit can fail here: a red
// validate on master always means the generator or the repository rules are broken, which is the
// point of running it everywhere.
//
// This checks shape only. Whether a particular hash *should* be listed is not knowable from here:
// removing one that is still in use looks identical to removing one that is obsolete.

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SIGNED = path.join(ROOT, 'src', 'hashes', 'hashlist-signed.json');
const PROVENANCE = path.join(ROOT, 'src', 'hashes', 'provenance.json');
const LEDGER = path.join(ROOT, 'src', 'hashes', 'ledger.json');

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

// The provenance record has one writer -- the signer, which owns the attribution rows, the
// commit-to-hash map, the refs snapshot its reconciler diffs against, and the sequence high-water.
// A malformed record takes the signer down, so shape is enforced here and on every PR. A
// grandfathered row (derived false) predates derivation and has no commit to point at.
function validateProvenance(hashes) {
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
    const commitOk = row && (
      (typeof row.commit === 'string' && /^[0-9a-f]{40}$/.test(row.commit))
      || (row.commit === null && row.derived !== true)
    );
    check(
      row && typeof row === 'object'
        && typeof row.published === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(row.published)
        && commitOk
        && (row.branch === null || typeof row.branch === 'string')
        && (row.tag === null || typeof row.tag === 'string')
        && (row.derived === undefined || typeof row.derived === 'boolean'),
      `provenance row is malformed: ${hash}`,
    );
  });

  Object.entries(record.commits || {}).forEach(([sha, hash]) => {
    check(/^[0-9a-f]{40}$/.test(sha), `commits map key is not a 40-character sha: ${sha}`);
    check(typeof hash === 'string' && /^[0-9a-f]{32}$/.test(hash), `commits map value is not a lowercase md5: ${hash}`);
  });
  Object.entries(record.refs || {}).forEach(([ref, sha]) => {
    check(ref.startsWith('refs/'), `refs snapshot key is not a ref: ${ref}`);
    check(typeof sha === 'string' && /^[0-9a-f]{40}$/.test(sha), `refs snapshot value is not a 40-character sha: ${ref}`);
  });

  // Post-cutover (the snapshot exists), membership is generated from the rows: a listed hash
  // without a row means the generator and its record have diverged.
  if (record.refs && hashes) {
    const unattributed = hashes.filter((hash) => !rows[hash]);
    check(unattributed.length === 0, `${unattributed.length} listed hashes have no provenance row: ${unattributed.slice(0, 3)}`);
  }

  process.stderr.write(`provenance: ${Object.keys(rows).length} rows, ${Object.keys(record.commits || {}).length} commits, ${Object.keys(record.refs || {}).length} refs, signed seq ${record.signed ? record.signed.seq : 'none'}\n`);
  return record;
}

// The ledger is the human-edited input: cull marks reviewed through PRs. A cull may still be
// listed here -- the signer applies it on its next run -- so consistency with the list is not
// checkable; shape is.
function validateLedger() {
  if (!fs.existsSync(LEDGER)) {
    process.stderr.write('no ledger yet, skipping\n');
    return;
  }

  let ledger;
  try {
    ledger = JSON.parse(fs.readFileSync(LEDGER, 'utf8'));
  } catch (error) {
    check(false, `ledger does not parse: ${error.message}`);
    return;
  }

  check(Array.isArray(ledger.culls), 'ledger.culls is not an array');
  (Array.isArray(ledger.culls) ? ledger.culls : []).forEach((cull, i) => {
    check(
      cull && typeof cull === 'object'
        && typeof cull.hash === 'string' && /^[0-9a-f]{32}$/.test(cull.hash)
        && typeof cull.reason === 'string' && cull.reason.length > 0
        && typeof cull.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(cull.date),
      `ledger cull ${i} is malformed: ${JSON.stringify(cull)}`,
    );
  });

  process.stderr.write(`ledger: ${Array.isArray(ledger.culls) ? ledger.culls.length : 0} culls\n`);
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
  const provenance = validateProvenance(hashes);
  validateLedger();
  validateSigned(hashes, provenance);

  if (failures.length) {
    failures.forEach((failure) => process.stderr.write(`  FAIL ${failure}\n`));
    process.exit(1);
  }
  process.stderr.write('ok\n');
}

if (require.main === module) main();
