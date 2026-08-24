#!/usr/bin/env node

// The single writer of everything src/hashes/ serves.
//
// Reconciles the published list against RunOnFlux/flux itself: diffs the remote's refs against the
// snapshot in the provenance record, fetches each new commit, computes its ZelBack tree hash from
// the bytes it fetched, and emits hashes.js, the signed document and the provenance record together.
// A hash value can enter the list through no other path. A dispatch carries pointers, never
// content, so the credential that sends one needs no write authority -- and the signature means
// "this commit's tree hashes to this value", not "this was in the repository when I ran".
//
// The payload is signed and transmitted as exact bytes in base64, so verification never depends on
// the signer and the verifier agreeing about JSON key order or whitespace.
//
// stdout carries exactly one line -- changed=false, changed=state or changed=signed -- read by the
// workflow to decide what to commit. Everything human goes to stderr.

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const LIST = path.join(ROOT, 'src', 'hashes', 'hashes.js');
const OUTPUT = path.join(ROOT, 'src', 'hashes', 'hashlist-signed.json');
const PROVENANCE = path.join(ROOT, 'src', 'hashes', 'provenance.json');
const LEDGER = path.join(ROOT, 'src', 'hashes', 'ledger.json');

const FLUX_REMOTE = process.env.FLUX_REMOTE || 'https://github.com/RunOnFlux/flux';

// fluxbench's pipeline, byte for byte -- flux CI's Check Hash step runs the same one. The awk
// strips filenames before the sort, so the hash depends only on the multiset of file contents;
// LC_ALL=C pins the sort.
const TREE_HASH_PIPELINE = "find ./ZelBack -type f -exec md5sum {} + | awk '{print $1}' | LC_ALL=C sort | md5sum | awk '{printf $1}'";

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

function buildSignedDocument(seq, issuedAt, hashes, privateKey) {
  if (!Number.isInteger(seq) || seq < 1) {
    throw new Error('seq must be a positive integer');
  }
  if (typeof issuedAt !== 'string' || Number.isNaN(Date.parse(issuedAt))) {
    throw new Error('issued_at must be a parseable date string');
  }
  if (!Array.isArray(hashes) || hashes.length === 0) {
    throw new Error('hashes must be a non-empty array');
  }
  if (!hashes.every((h) => typeof h === 'string' && /^[0-9a-f]{32}$/.test(h))) {
    throw new Error('every hash must be a lowercase 32-character md5');
  }

  const payload = Buffer.from(JSON.stringify({ seq, issued_at: issuedAt, hashes }), 'utf8');
  const signature = crypto.sign(null, payload, privateKey);

  return {
    payload_b64: payload.toString('base64'),
    sig_b64: signature.toString('base64'),
  };
}

function previousDocument() {
  if (!fs.existsSync(OUTPUT)) {
    return null;
  }
  const document = JSON.parse(fs.readFileSync(OUTPUT, 'utf8'));
  return JSON.parse(Buffer.from(document.payload_b64, 'base64').toString('utf8'));
}

// The provenance record is this writer's own state: attribution rows, the commit-to-hash map, the
// refs snapshot the reconciler diffs against, and the highest sequence ever signed. Absence is the
// state before the first run and starts the cutover bootstrap. A record that exists but does not
// parse is a red run: treating corruption as absence is exactly the restart this exists to prevent.
function readProvenance() {
  if (!fs.existsSync(PROVENANCE)) {
    return null;
  }
  const record = JSON.parse(fs.readFileSync(PROVENANCE, 'utf8'));
  if (record.signed !== undefined && record.signed !== null
      && (!Number.isInteger(record.signed.seq) || record.signed.seq < 1)) {
    throw new Error(`provenance signed.seq is not a positive integer: ${record.signed.seq}`);
  }
  return record;
}

// The ledger is the human-edited input: cull marks that take entries out of the list through a
// reviewed PR. The signer reads it and never writes it, which is what lets the workflow trigger on
// pushes to it without ever retriggering itself. Malformed is a red run, not a skip.
function readLedger() {
  if (!fs.existsSync(LEDGER)) {
    return { culls: [] };
  }
  const ledger = JSON.parse(fs.readFileSync(LEDGER, 'utf8'));
  if (!Array.isArray(ledger.culls)) {
    throw new Error('ledger.culls is not an array');
  }
  ledger.culls.forEach((cull) => {
    if (!cull || typeof cull.hash !== 'string' || !/^[0-9a-f]{32}$/.test(cull.hash)) {
      throw new Error(`ledger cull without a valid hash: ${JSON.stringify(cull)}`);
    }
  });
  return ledger;
}

function git(args, options = {}) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
}

// refs/heads/* as listed; refs/tags/* resolved to the commit they point at (the ^{} peel when the
// tag is annotated). One request regardless of ref count.
function lsRemoteRefs(remote) {
  const refs = {};
  const peeled = {};
  git(['ls-remote', '--heads', '--tags', remote]).split('\n').filter(Boolean).forEach((line) => {
    const [sha, ref] = line.split('\t');
    if (ref.endsWith('^{}')) {
      peeled[ref.slice(0, -3)] = sha;
    } else {
      refs[ref] = sha;
    }
  });
  Object.entries(peeled).forEach(([ref, sha]) => { refs[ref] = sha; });
  return refs;
}

function ensureCacheRepo() {
  const dir = process.env.FLUX_CACHE_DIR || path.join(os.tmpdir(), 'flux-hash-cache');
  if (!fs.existsSync(path.join(dir, '.git'))) {
    fs.mkdirSync(dir, { recursive: true });
    git(['init', '--quiet'], { cwd: dir });
  }
  return dir;
}

// Fetch the named commit from the official remote and hash the pristine tree in a throwaway
// worktree. Nothing from the fetched tree is ever executed; the pipeline only reads bytes.
function deriveTreeHash(cache, sha) {
  git(['fetch', '--quiet', '--depth', '1', FLUX_REMOTE, sha], { cwd: cache });
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'flux-tree-'));
  const worktree = path.join(parent, 'wt');
  try {
    git(['worktree', 'add', '--quiet', '--detach', worktree, sha], { cwd: cache });
    const hash = execFileSync('bash', ['-c', TREE_HASH_PIPELINE], { cwd: worktree, encoding: 'utf8' }).trim();
    if (!/^[0-9a-f]{32}$/.test(hash)) {
      throw new Error(`tree hash pipeline produced "${hash}"`);
    }
    return hash;
  } finally {
    try {
      git(['worktree', 'remove', '--force', worktree], { cwd: cache });
    } catch (error) { /* the worktree was never created */ }
    fs.rmSync(parent, { recursive: true, force: true });
  }
}

function writeList(hashes) {
  const lines = ['function getHashes() {', '  return ['];
  hashes.forEach((hash) => lines.push(`    '${hash}',`));
  lines.push('  ];', '}', '', 'module.exports = {', '  getHashes,', '};', '');
  fs.writeFileSync(LIST, lines.join('\n'));
}

function refLabel(ref) {
  return ref.startsWith('refs/heads/')
    ? { branch: ref.slice('refs/heads/'.length), tag: null }
    : { branch: null, tag: ref.slice('refs/tags/'.length) };
}

function dispatchLabel() {
  const ref = process.env.DISPATCH_REF || null;
  if (!ref) {
    return { branch: null, tag: null };
  }
  return process.env.DISPATCH_REF_TYPE === 'tag' ? { branch: null, tag: ref } : { branch: ref, tag: null };
}

function main() {
  const seedB64 = process.env.HASHLIST_SIGNING_SEED_B64;
  if (!seedB64) {
    throw new Error('HASHLIST_SIGNING_SEED_B64 is not set');
  }

  // eslint-disable-next-line global-require
  const currentList = require('../src/hashes/hashes').getHashes();
  const previous = previousDocument();
  const provenance = readProvenance() || {};
  const ledger = readLedger();
  const before = JSON.stringify(provenance);

  const today = new Date().toISOString().slice(0, 10);
  const rows = provenance.hashes || {};
  const commits = provenance.commits || {};
  const snapshot = provenance.refs || null;

  const current = lsRemoteRefs(FLUX_REMOTE);
  process.stderr.write(`flux remote: ${Object.keys(current).length} refs\n`);

  // Cutover bootstrap: no snapshot means nothing has been derived yet. Grandfather everything
  // already listed and snapshot the remote as it stands, so only movement from here on is derived.
  if (!snapshot) {
    currentList.forEach((hash) => {
      if (!rows[hash]) {
        rows[hash] = {
          published: today, commit: null, branch: null, tag: null, derived: false,
        };
      } else if (rows[hash].derived === undefined) {
        rows[hash].derived = false;
      }
    });
    process.stderr.write(`bootstrap: grandfathered ${currentList.length} entries, snapshotting ${Object.keys(current).length} refs\n`);
  }

  // The work set: every ref that moved since the snapshot, keyed by commit. A tag riding a commit
  // that is also a branch tip annotates rather than duplicates.
  const work = new Map();
  if (snapshot) {
    Object.entries(current).forEach(([ref, sha]) => {
      if (snapshot[ref] === sha) return;
      // A tag that MOVED keeps its original attribution; only genuinely new tags join the set.
      if (ref.startsWith('refs/tags/') && snapshot[ref] !== undefined) return;
      const label = refLabel(ref);
      if (!work.has(sha)) {
        work.set(sha, label);
      } else {
        // A commit arriving as branch tip and tag in the same run keeps both labels, whichever
        // ref was seen first.
        const existing = work.get(sha);
        if (label.tag && !existing.tag) existing.tag = label.tag;
        if (label.branch && !existing.branch) existing.branch = label.branch;
      }
    });
  }

  const dispatchCommit = (process.env.DISPATCH_COMMIT || '').toLowerCase() || null;
  const claimed = (process.env.DISPATCH_CLAIMED_HASH || '').toLowerCase() || null;
  if (dispatchCommit && !/^[0-9a-f]{40}$/.test(dispatchCommit)) {
    throw new Error(`dispatched commit is not a 40-character sha: ${dispatchCommit}`);
  }
  if (dispatchCommit && !work.has(dispatchCommit)) {
    // Label from our own view of the remote first; the dispatch's ref fields are a fallback label
    // for a ref that moved past the commit before we looked, never authority.
    const ownRef = Object.keys(current).find((ref) => current[ref] === dispatchCommit);
    work.set(dispatchCommit, ownRef ? refLabel(ownRef) : dispatchLabel());
  }
  if (dispatchCommit && claimed && commits[dispatchCommit] && commits[dispatchCommit] !== claimed) {
    throw new Error(`claimed hash ${claimed} does not match ${commits[dispatchCommit]} already derived for ${dispatchCommit}`);
  }

  // Derive. A failed fetch of a dispatched commit is a red run -- the caller named a commit the
  // official repository will not serve. A failed fetch from the ref sweep keeps that ref's old
  // snapshot entry, so the next run retries it.
  const failedRefs = new Set();
  const cache = ensureCacheRepo();
  work.forEach((label, sha) => {
    if (commits[sha]) {
      const row = rows[commits[sha]];
      if (row && label.tag && !row.tag) {
        row.tag = label.tag;
      }
      return;
    }
    let hash;
    try {
      hash = deriveTreeHash(cache, sha);
    } catch (error) {
      if (sha === dispatchCommit) {
        throw new Error(`dispatched commit ${sha}: ${error.message}`);
      }
      process.stderr.write(`skipping ${sha}: ${error.message}\n`);
      Object.entries(current).forEach(([ref, s]) => { if (s === sha) failedRefs.add(ref); });
      return;
    }
    if (sha === dispatchCommit && claimed && claimed !== hash) {
      throw new Error(`claimed hash ${claimed} does not match derived ${hash} for ${sha} -- environment drift or a hostile dispatch, either must be loud`);
    }
    commits[sha] = hash;
    if (!rows[hash]) {
      // First attribution wins: a hash republished from another branch keeps its original row.
      rows[hash] = {
        published: today, commit: sha, branch: label.branch, tag: label.tag, derived: true,
      };
      process.stderr.write(`derived ${hash} from ${sha.slice(0, 9)} (${label.tag || label.branch || 'unlabelled'})\n`);
    } else if (label.tag && !rows[hash].tag) {
      rows[hash].tag = label.tag;
    }
  });

  const nextRefs = {};
  Object.entries(current).forEach(([ref, sha]) => {
    if (failedRefs.has(ref)) {
      if (snapshot && snapshot[ref] !== undefined) {
        nextRefs[ref] = snapshot[ref];
      }
      return;
    }
    nextRefs[ref] = sha;
  });

  // Membership: what is listed, minus culls, plus everything derived that is not yet listed.
  const culled = new Set(ledger.culls.map((cull) => cull.hash));
  const listed = new Set(currentList);
  const retained = currentList.filter((hash) => !culled.has(hash));
  const additions = Object.keys(rows).filter(
    (hash) => rows[hash].derived === true && !listed.has(hash) && !culled.has(hash),
  );
  const newList = retained.concat(additions);

  // Monotonicity: an entry leaves the list only when the ledger says so. The append-with-cull
  // construction above cannot trip this today -- it exists so that a future change to true
  // regeneration-from-rows turns a dropped entry into a red run, never a signed loss
  // (mutation-tested: it catches exactly that).
  const surviving = new Set(newList);
  currentList.forEach((hash) => {
    if (!surviving.has(hash) && !culled.has(hash)) {
      throw new Error(`entry ${hash} would vanish without a ledger cull -- refusing to publish`);
    }
  });
  if (newList.length === 0) {
    throw new Error('refusing to publish an empty list');
  }
  if (surviving.size !== newList.length) {
    throw new Error('the regenerated list contains duplicates -- refusing to publish');
  }

  const listChanged = newList.length !== currentList.length
    || newList.some((hash, i) => hash !== currentList[i]);
  // No document has ever been published: the bootstrap run signs even an unchanged list. This is
  // also the first proof that the stored seed matches the pinned key.
  const mustSign = !previous;

  provenance.hashes = rows;
  provenance.commits = commits;
  provenance.refs = nextRefs;

  if (!listChanged && !mustSign) {
    if (JSON.stringify(provenance) === before) {
      process.stderr.write(`nothing changed at seq ${previous.seq}\n`);
      process.stdout.write('changed=false\n');
      return;
    }
    // Attribution, tag annotations or the snapshot advanced with the membership intact: worth a
    // commit, not worth a sequence.
    fs.writeFileSync(PROVENANCE, `${JSON.stringify(provenance, null, 2)}\n`);
    process.stderr.write(`state advanced, membership unchanged at seq ${previous.seq}\n`);
    process.stdout.write('changed=state\n');
    return;
  }

  const highWater = Math.max(
    previous ? previous.seq : 0,
    provenance.signed ? provenance.signed.seq : 0,
  );
  const seq = highWater + 1;
  const issuedAt = new Date().toISOString();
  const privateKey = privateKeyFromSeed(seedB64);
  const document = buildSignedDocument(seq, issuedAt, newList, privateKey);
  provenance.signed = { seq, issued_at: issuedAt };

  writeList(newList);
  fs.writeFileSync(OUTPUT, `${JSON.stringify(document, null, 2)}\n`);
  fs.writeFileSync(PROVENANCE, `${JSON.stringify(provenance, null, 2)}\n`);
  process.stderr.write(`signed seq ${seq} over ${newList.length} hashes (${additions.length} added, ${currentList.length - retained.length} culled)\n`);
  process.stderr.write(`public key (raw, hex): ${rawPublicKey(privateKey).toString('hex')}\n`);
  process.stdout.write('changed=signed\n');
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`sign-hashlist: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = {
  privateKeyFromSeed, rawPublicKey, buildSignedDocument, readProvenance, readLedger,
};
