# Signing the hash list

`src/hashes/hashlist-signed.json` is the list this repository publishes, signed with Ed25519 so consumers can verify
it came from us rather than trusting the transport or whatever relayed it.

It is published **alongside** `src/hashes/hashes.js`, not instead of it. Both are served.

## The document

`{ payload_b64, sig_b64 }`, where the payload is the exact signed bytes — a JSON object
`{ seq, issued_at, hashes }`. The signature covers the transmitted bytes, so verification never
depends on signer and verifier agreeing about JSON key order or whitespace.

`seq` increases by one per signing run and never restarts. Its high-water mark is recorded in the
provenance record beside the document, and the signer takes the next sequence from whichever of the
two is higher — so losing the document, however that happens, does not reset the sequence.
`validate.js` refuses a document whose sequence is not exactly the recorded high-water.

## The provenance record

`src/hashes/provenance.json`, outside the signed payload, with **one writer — the signing
workflow**, which derives every post-cutover entry itself from commits it fetches from
`RunOnFlux/flux`:

- a **row per listed hash** — `published` date, `commit`, `branch`, `tag`, `derived`. This is what
  makes an entry attributable later: the list itself is opaque md5s, and the commit that produced
  an entry can stop existing (a force-push, a branch deleted after merge). First attribution wins;
  a new tag on a known commit annotates the existing row. Rows with `derived: false` predate
  derivation (grandfathered at cutover) and have no commit to point at.
- a **commits map** (`sha → hash`) so nothing is fetched or hashed twice, and a **refs snapshot**
  of the flux remote, which is what the reconciler diffs against — a publication request that gets
  lost is repaired by the next run reconciling the full delta.
- **`signed`** — the sequence high-water and `issued_at`, stamped in the same commit as the signed
  document.

`src/hashes/ledger.json` is the one human-edited input: cull marks, reviewed through PRs. The
signer reads it and never writes it. The three output files are generated — `validate` fails any
PR that edits them directly.

## Keys

Consumers pin a set of public keys and accept a document signed by any one of them, so a second key
can take over without those consumers needing an update.

| key | public key (raw ed25519, hex) | custody | use |
|---|---|---|---|
| 1 | `3023cb5e01dc22257ac5c31c4d12106cd0d58fa2005f867b3fdc5d303f6446ec` | CI, secret `HASHLIST_SIGNING_SEED_B64` in the `hashlist-signing` environment | day to day |
| 2 | `fee7b0ccf2323954af68a249eaa61f957239eb222329e08a5b6a50ced649bae8` | cold, offline | continuity only |

### Key 1

Generated 2026-08-14 straight into the secret `HASHLIST_SIGNING_SEED_B64`, which lives in the
`hashlist-signing` GitHub Environment whose deployment branch policy admits `master` only — a
workflow run on any other ref is refused before its first step, so a branch push cannot read it.
**There is no copy of the private half anywhere else, on purpose** — key 2 covers its loss, and a
second copy would only widen where it can leak from.

To replace it, generate a new one the same way:

```sh
node -e '
const crypto = require("crypto");
const seed = crypto.randomBytes(32);
const key = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"), seed]),
  format: "der", type: "pkcs8",
});
process.stderr.write("public_key_hex=" + crypto.createPublicKey(key)
  .export({format:"der", type:"spki"}).subarray(12).toString("hex") + "\n");
process.stdout.write(seed.toString("base64"));
' | gh secret set HASHLIST_SIGNING_SEED_B64 --repo RunOnFlux/fluxhashes
```

The seed goes down the pipe and is never printed or written to disk. Put the printed public key in
the table above and in `scripts/verify-hashlist.js`.

### Key 2

Generated offline, private half never on a networked machine, stored with the release signing
material. Not used in normal operation.

Its purpose is continuity: without a second key, losing key 1 would mean nothing new could be
published until consumers were updated with a replacement.

It does not provide revocation — removing a key from the pinned set requires updating consumers.
Two keys held in the same place buy nothing; the separation is the point.

### The deploy key

The signer pushes to `master` over SSH with a write deploy key, `HASHLIST_DEPLOY_KEY` in the same
environment — the one bypass on the master ruleset, which otherwise admits only reviewed PRs with
`validate` green (repository admins included). The run's own `GITHUB_TOKEN` stays read-only. To
rotate: generate a fresh keypair, replace the repository deploy key and the environment secret;
the ruleset's `DeployKey` bypass covers whatever write keys the repository holds, so it needs no
change — which is also why the repository must hold exactly this one write deploy key.

## Trust

Anyone who can land a workflow change on `master` can read the secrets; a GitHub secret is an
access-controlled environment variable, not a vault. Environment scoping means landing that change
requires a reviewed merge — a branch push is no longer enough. Secrets are not passed to workflows
triggered by a pull request from a fork, which matters because this repository is public.
