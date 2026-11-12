#!/usr/bin/env node

// Publishes the signed hash list to the CDN origin as the `components` document `hashlist`, and
// returns only once the origin offers it: every CDN holds it, so every node can read it.
//
// It publishes when the origin's list has a lower sequence than the signed one, or when the origin
// has none. A list the origin already holds is not sent again, and the run still waits for it to
// be offered, so a run that follows an interrupted one finishes its work.
//
// The origin identifies this publisher by its client certificate, which the origin's config limits
// to the `hashlist` document. The certificate proves nothing about the list: consumers verify the
// list's own signature.
//
// Environment: ORIGIN_URL (https://<host>/origin), ORIGIN_CERT and ORIGIN_KEY (PEM text),
// ORIGIN_CA (PEM text; unset to use the system's CAs), PUBLISH_WAIT_S (default 1800).

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const { verifyDocument, PINNED_PUBLIC_KEYS } = require('./verify-hashlist');

const ARTEFACT = 'components/hashlist';
const FILE = 'document';
const DEFAULT_WAIT_S = 1800;
const POLL_MS = 10000;
const REQUEST_TIMEOUT_MS = 60000;

function request(origin, tls, method, resource, body) {
  const url = new URL(`${origin}/${resource}`);
  const transport = url.protocol === 'https:' ? https : http;
  const headers = {};
  if (body !== undefined) {
    headers['Content-Length'] = body.length;
  }
  return new Promise((resolve, reject) => {
    const req = transport.request(url, {
      method, headers, timeout: REQUEST_TIMEOUT_MS, ...tls,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`${method} ${resource}: no answer in ${REQUEST_TIMEOUT_MS / 1000} s`)));
    req.on('error', reject);
    req.end(body);
  });
}

// The origin's side of a publish, over HTTP. `tls` holds the client certificate.
function originClient(origin, tls = {}) {
  async function expect(method, resource, body, accepted = [200]) {
    const answer = await request(origin, tls, method, resource, body);
    if (!accepted.includes(answer.status)) {
      throw new Error(`${method} ${resource}: ${answer.status} ${answer.body.toString('utf8').slice(0, 300)}`);
    }
    return answer;
  }

  return {
    // The origin's entry for the document, or null: its state and the list it holds.
    async held() {
      const index = JSON.parse((await expect('GET', 'index.json')).body.toString('utf8'));
      const entry = (index.artefacts || []).find((e) => e.kind === 'components' && e.id === 'hashlist');
      if (!entry || entry.state === 'retiring') {
        return null;
      }
      const answer = await expect('GET', `artefacts/${ARTEFACT}/${FILE}`, undefined, [200, 404]);
      if (answer.status === 404) {
        return null;
      }
      return { state: entry.state, document: answer.body };
    },

    async publish(document) {
      const incoming = `incoming/${ARTEFACT}`;
      await expect('DELETE', `${incoming}/${FILE}`);
      await expect('PUT', `${incoming}/${FILE}?offset=0`, document);
      await expect('POST', `${incoming}/commit`, Buffer.from(JSON.stringify({
        channel: 'release',
        files: [{ name: FILE, bytes: document.length, sha256: crypto.createHash('sha256').update(document).digest('hex') }],
        names: [],
      })));
      await expect('POST', `artefacts/${ARTEFACT}/promote`);
    },
  };
}

// The sequence of a list the origin holds. One that does not verify counts as no list: the
// signed one replaces it.
function heldSeq(held, publicKeys) {
  if (held === null) {
    return null;
  }
  try {
    return verifyDocument(JSON.parse(held.document.toString('utf8')), publicKeys).seq;
  } catch (error) {
    return null;
  }
}

// Brings the origin to offer the list `document` (sequence `seq`). Resolves to whether it
// published; rejects when the origin holds a later list, or does not offer this one in time.
async function reconcile({
  client, document, seq, publicKeys = PINNED_PUBLIC_KEYS, waitS = DEFAULT_WAIT_S, pollMs = POLL_MS, log = () => {},
}) {
  const before = heldSeq(await client.held(), publicKeys);
  const published = before === null || before < seq;
  if (published) {
    log(`the origin holds ${before === null ? 'no list' : `seq ${before}`}: publishing seq ${seq}`);
    await client.publish(document);
  }

  const deadline = Date.now() + waitS * 1000;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const held = await client.held();
    const now = heldSeq(held, publicKeys);
    if (now !== null && now > seq) {
      throw new Error(`the origin holds seq ${now}, above the signed list's ${seq}`);
    }
    if (now === seq && held.state === 'offered') {
      log(`the origin offers seq ${seq}`);
      return published;
    }
    if (Date.now() >= deadline) {
      throw new Error(`the origin did not offer seq ${seq} within ${waitS} s`);
    }
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => { setTimeout(resolve, pollMs); });
  }
}

async function main(env) {
  const origin = (env.ORIGIN_URL || '').replace(/\/+$/, '');
  if (!origin.startsWith('https://')) {
    throw new Error('ORIGIN_URL must be an https URL');
  }
  if (!env.ORIGIN_CERT || !env.ORIGIN_KEY) {
    throw new Error('ORIGIN_CERT and ORIGIN_KEY must hold the publisher certificate and its key');
  }
  const waitS = env.PUBLISH_WAIT_S === undefined || env.PUBLISH_WAIT_S === '' ? DEFAULT_WAIT_S : Number(env.PUBLISH_WAIT_S);
  if (!Number.isFinite(waitS) || waitS < 0) {
    throw new Error('PUBLISH_WAIT_S must be a number of seconds');
  }
  const tls = { cert: env.ORIGIN_CERT, key: env.ORIGIN_KEY };
  if (env.ORIGIN_CA) {
    tls.ca = env.ORIGIN_CA;
  }

  const document = fs.readFileSync(path.join(__dirname, '..', 'src', 'hashes', 'hashlist-signed.json'));
  const { seq } = verifyDocument(JSON.parse(document.toString('utf8')), PINNED_PUBLIC_KEYS);

  const published = await reconcile({
    client: originClient(origin, tls),
    document,
    seq,
    waitS,
    log: (line) => process.stderr.write(`${line}\n`),
  });
  process.stdout.write(`published=${published}\n`);
}

if (require.main === module) {
  main(process.env).catch((error) => {
    process.stderr.write(`publish-hashlist: ${error.message}\n`);
    process.exit(1);
  });
}

module.exports = { originClient, reconcile };
