// scripts/publish-hashlist.js against a local origin that speaks the CDN origin's publish protocol:
// upload, commit, promote, and an index whose entry turns from staged to offered.

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');
const { test } = require('node:test');

const { originClient, reconcile } = require('../../scripts/publish-hashlist');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'publish-hashlist.js');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const KEYS = [publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex')];

function signed(seq, key = privateKey) {
  const payload = Buffer.from(JSON.stringify({ seq, issued_at: '2026-01-01T00:00:00.000Z', hashes: ['00'.repeat(16)] }));
  return Buffer.from(JSON.stringify({
    payload_b64: payload.toString('base64'),
    sig_b64: crypto.sign(null, payload, key).toString('base64'),
  }));
}

// `entry`: what the origin holds ({ state, document } or null). A promoted document is staged, and
// offered once the index has been read `offerAfter` more times. `refuse` answers 403 to one method.
async function fakeOrigin({ entry = null, offerAfter = 2, refuse = null } = {}) {
  const origin = {
    entry, offerAfter, incoming: null, pending: null, writes: [], reads: 0,
  };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, 'http://origin');
      const route = `${req.method} ${url.pathname}`;
      const answer = (status, value) => {
        res.writeHead(status);
        res.end(Buffer.isBuffer(value) || typeof value === 'string' ? value : JSON.stringify(value));
      };
      if (req.method !== 'GET') {
        origin.writes.push(route);
        if (req.method === refuse) {
          answer(403, 'this certificate may not write components/hashlist');
          return;
        }
      }
      switch (route) {
        case 'GET /origin/index.json': {
          origin.reads += 1;
          if (origin.entry && origin.entry.state === 'staged') {
            origin.entry.left -= 1;
            if (origin.entry.left <= 0) {
              origin.entry.state = 'offered';
            }
          }
          const artefacts = [{ kind: 'arcane', id: '1793300000', state: 'offered' }];
          if (origin.entry) {
            artefacts.push({ kind: 'components', id: 'hashlist', state: origin.entry.state });
          }
          answer(200, { generation: origin.reads, artefacts });
          return;
        }
        case 'GET /origin/artefacts/components/hashlist/document':
          if (origin.entry) answer(200, origin.entry.document); else answer(404, 'none');
          return;
        case 'DELETE /origin/incoming/components/hashlist/document':
          origin.incoming = null;
          answer(200, { bytes: 0 });
          return;
        case 'PUT /origin/incoming/components/hashlist/document': {
          const size = origin.incoming ? origin.incoming.length : 0;
          if (url.searchParams.get('offset') !== String(size)) {
            answer(409, { bytes: size });
            return;
          }
          origin.incoming = Buffer.concat([origin.incoming || Buffer.alloc(0), body]);
          answer(200, { bytes: origin.incoming.length });
          return;
        }
        case 'POST /origin/incoming/components/hashlist/commit': {
          const commit = JSON.parse(body.toString('utf8'));
          const [file] = commit.files;
          const sha256 = crypto.createHash('sha256').update(origin.incoming || Buffer.alloc(0)).digest('hex');
          if (commit.channel !== 'release' || commit.files.length !== 1 || file.name !== 'document'
            || file.bytes !== origin.incoming.length || file.sha256 !== sha256 || commit.names.length !== 0) {
            answer(422, 'not what was uploaded');
            return;
          }
          origin.pending = origin.incoming;
          origin.incoming = null;
          answer(200, { state: 'pending' });
          return;
        }
        case 'POST /origin/artefacts/components/hashlist/promote':
          if (!origin.pending) {
            answer(409, 'hashlist has no pending version');
            return;
          }
          origin.entry = { state: 'staged', document: origin.pending, left: origin.offerAfter };
          origin.pending = null;
          answer(200, { state: 'staged' });
          return;
        default:
          answer(404, `no route ${route}`);
      }
    });
  });
  await new Promise((resolve) => { server.listen(0, '127.0.0.1', resolve); });
  origin.url = `http://127.0.0.1:${server.address().port}/origin`;
  origin.close = () => new Promise((resolve) => { server.close(resolve); });
  return origin;
}

function run(origin, seq, options = {}) {
  return reconcile({
    client: originClient(origin.url), document: signed(seq), seq, publicKeys: KEYS, pollMs: 5, waitS: 5, ...options,
  });
}

test('an origin with no list is given the signed one, and the run ends once it is offered', async (t) => {
  const origin = await fakeOrigin();
  t.after(origin.close);
  assert.equal(await run(origin, 7), true);
  assert.equal(origin.entry.state, 'offered');
  assert.deepEqual(origin.entry.document, signed(7));
});

test('an origin with a lower sequence is given the signed list', async (t) => {
  const origin = await fakeOrigin({ entry: { state: 'offered', document: signed(6) } });
  t.after(origin.close);
  assert.equal(await run(origin, 7), true);
  assert.deepEqual(origin.entry.document, signed(7));
  assert.equal(origin.entry.state, 'offered');
});

test('a list the origin offers is not sent again', async (t) => {
  const origin = await fakeOrigin({ entry: { state: 'offered', document: signed(7) } });
  t.after(origin.close);
  assert.equal(await run(origin, 7), false);
  assert.deepEqual(origin.writes, []);
});

test('a list the origin holds but does not offer yet is waited for, not sent again', async (t) => {
  const origin = await fakeOrigin({ entry: { state: 'staged', document: signed(7), left: 4 } });
  t.after(origin.close);
  assert.equal(await run(origin, 7), false);
  assert.deepEqual(origin.writes, []);
  assert.equal(origin.entry.state, 'offered');
  assert.ok(origin.reads >= 4);
});

test('the run does not end while the list is only staged', async (t) => {
  const origin = await fakeOrigin({ offerAfter: 1e9 });
  t.after(origin.close);
  await assert.rejects(run(origin, 7, { waitS: 0.2 }), /did not offer seq 7 within 0.2 s/);
  assert.equal(origin.entry.state, 'staged');
});

test('an origin holding a later list stops the run and is left alone', async (t) => {
  const origin = await fakeOrigin({ entry: { state: 'offered', document: signed(9) } });
  t.after(origin.close);
  await assert.rejects(run(origin, 7), /holds seq 9, above the signed list's 7/);
  assert.deepEqual(origin.writes, []);
});

test('a list on the origin that no pinned key signed is replaced', async (t) => {
  const stranger = crypto.generateKeyPairSync('ed25519').privateKey;
  const origin = await fakeOrigin({ entry: { state: 'offered', document: signed(99, stranger) } });
  t.after(origin.close);
  assert.equal(await run(origin, 7), true);
  assert.deepEqual(origin.entry.document, signed(7));
});

test('a retiring list counts as none', async (t) => {
  const origin = await fakeOrigin({ entry: { state: 'retiring', document: signed(7) } });
  t.after(origin.close);
  assert.equal(await run(origin, 7), true);
  assert.equal(origin.entry.state, 'offered');
});

['DELETE', 'PUT', 'POST'].forEach((method) => {
  test(`an origin that refuses the ${method} fails the run with its answer`, async (t) => {
    const origin = await fakeOrigin({ refuse: method });
    t.after(origin.close);
    await assert.rejects(run(origin, 7), new RegExp(`${method} .*: 403 this certificate may not write`));
    assert.equal(origin.entry, null);
  });
});

test('the command refuses an origin that is not https, and a missing certificate', () => {
  const command = (env) => spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });
  const plain = command({ ORIGIN_URL: 'http://127.0.0.1:1/origin', ORIGIN_CERT: 'c', ORIGIN_KEY: 'k' });
  assert.equal(plain.status, 1);
  assert.match(plain.stderr, /ORIGIN_URL must be an https URL/);
  const bare = command({ ORIGIN_URL: 'https://127.0.0.1:1/origin' });
  assert.equal(bare.status, 1);
  assert.match(bare.stderr, /ORIGIN_CERT and ORIGIN_KEY/);
});
