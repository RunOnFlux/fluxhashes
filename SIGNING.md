# Signing the hash list

`src/hashes/hashlist-signed.json` is the list this repository publishes, signed with Ed25519 so consumers can verify
it came from us rather than trusting the transport or whatever relayed it.

It is published **alongside** `src/hashes/hashes.js`, not instead of it. Both are served.

## Keys

Consumers pin a set of public keys and accept a document signed by any one of them, so a second key
can take over without those consumers needing an update.

| key | public key (raw ed25519, hex) | custody | use |
|---|---|---|---|
| 1 | `3023cb5e01dc22257ac5c31c4d12106cd0d58fa2005f867b3fdc5d303f6446ec` | CI, repository secret `HASHLIST_SIGNING_SEED_B64` | day to day |
| 2 | `fee7b0ccf2323954af68a249eaa61f957239eb222329e08a5b6a50ced649bae8` | cold, offline | continuity only |

### Key 1

Generated 2026-08-14 straight into the repository secret `HASHLIST_SIGNING_SEED_B64`. **There is no
copy of the private half anywhere else, on purpose** — key 2 covers its loss, and a second copy would
only widen where it can leak from.

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

## Trust

Anyone who can land a workflow change on `master` can read the secret; a GitHub secret is an
access-controlled environment variable, not a vault. It is not passed to workflows triggered by a
pull request from a fork, which matters because this repository is public.
