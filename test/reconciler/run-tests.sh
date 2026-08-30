#!/usr/bin/env bash
# Local logic tests for the reconciler. GitHub platform semantics are proven separately (the
# 2026-08-24 sandbox proofs); this drives scripts/sign-hashlist.js against a local fake flux
# remote through every state transition the design names.
set -u

# Everything scratch lives in a temp dir: the repository itself is never written to, so this is
# safe to run from a clean checkout and leaves nothing behind.
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
WORK="$TMP/work"
FLUX="$TMP/fake-flux"
export HASHLIST_SIGNING_SEED_B64="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="  # test only
PASS=0; FAIL=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }

run_signer() {  # -> stdout line in $RESULT, exit code in $RC
  cd "$WORK"
  RESULT=$(node scripts/sign-hashlist.js 2>"$TMP/last-stderr.txt"); RC=$?
  cd "$HERE"
}

jsonq() { node -e "const j=JSON.parse(require('fs').readFileSync('$1','utf8')); console.log($2);"; }
listq() { node -e "console.log(require('$WORK/src/hashes/hashes.js').getHashes()$1);"; }
tree_hash() { (cd "$1" && find ./ZelBack -type f -exec md5sum {} + | awk '{print $1}' | LC_ALL=C sort | md5sum | awk '{printf $1}'); }

# ---------- setup: fake flux remote with two files, master + dev ----------
mkdir -p "$FLUX/ZelBack/src"
git -C "$FLUX" init -q -b master
git -C "$FLUX" config user.email t@t; git -C "$FLUX" config user.name t
git -C "$FLUX" config uploadpack.allowAnySHA1InWant true
echo 'alpha' > "$FLUX/ZelBack/src/a.js"; echo 'beta' > "$FLUX/ZelBack/src/b.js"; echo 'root' > "$FLUX/readme.md"
git -C "$FLUX" add -A; git -C "$FLUX" commit -qm c1
HASH1=$(tree_hash "$FLUX")

mkdir -p "$WORK"
tar -c -C "$SRC" --exclude=.git --exclude=node_modules . | tar -x -C "$WORK"
rm -f "$WORK/src/hashes/hashlist-signed.json" "$WORK/src/hashes/provenance.json"
# Pin the test key in the work copy, the same substitution the sandbox rehearsals make.
node -e "
const fs=require('fs');
const {privateKeyFromSeed, rawPublicKey}=require('$WORK/scripts/sign-hashlist.js');
const pub=rawPublicKey(privateKeyFromSeed(process.env.HASHLIST_SIGNING_SEED_B64)).toString('hex');
const p='$WORK/scripts/verify-hashlist.js';
const src=fs.readFileSync(p,'utf8').replace(/const PINNED_PUBLIC_KEYS = \[[^\]]*\];/, \"const PINNED_PUBLIC_KEYS = [\n  '\"+pub+\"',\n];\");
fs.writeFileSync(p,src);
"
printf 'function getHashes() {\n  return [\n    '\''%s'\'',\n    '\''ffffffffffffffffffffffffffffffff'\'',\n  ];\n}\n\nmodule.exports = {\n  getHashes,\n};\n' "$HASH1" > "$WORK/src/hashes/hashes.js"
export FLUX_REMOTE="$FLUX"
export FLUX_CACHE_DIR="$TMP/cache"

# ---------- 1. bootstrap: signs the grandfathered list, derives nothing ----------
say "1 bootstrap"
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=signed" ] && ok "bootstrap signs" || bad "bootstrap: rc=$RC result=$RESULT"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'j.signed.seq')" = 1 ] && ok "seq 1" || bad "seq"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH1'].derived")" = "false" ] && ok "grandfathered underived" || bad "grandfather"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH1'].commit")" = "null" ] && ok "grandfathered commit null" || bad "commit null"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'Object.keys(j.refs).length')" = 1 ] && ok "refs snapshotted" || bad "refs"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'Object.keys(j.commits).length')" = 0 ] && ok "nothing derived at bootstrap" || bad "derived at bootstrap"
node -e "
const {verifyDocument} = require('$WORK/scripts/verify-hashlist.js');
const {privateKeyFromSeed, rawPublicKey} = require('$WORK/scripts/sign-hashlist.js');
const pub = rawPublicKey(privateKeyFromSeed(process.env.HASHLIST_SIGNING_SEED_B64)).toString('hex');
const doc = JSON.parse(require('fs').readFileSync('$WORK/src/hashes/hashlist-signed.json','utf8'));
const p = verifyDocument(doc, [pub]);
if (p.seq !== 1 || p.hashes.length !== 2) throw new Error('payload wrong');
" && ok "document verifies under the test key" || bad "verify"

# ---------- 2. unchanged rerun ----------
say "2 unchanged rerun"
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=false" ] && ok "no-op" || bad "rerun: rc=$RC result=$RESULT"

# ---------- 3. new ZelBack commit on master: derived, appended, seq 2 ----------
say "3 new tree commit"
echo 'gamma' >> "$FLUX/ZelBack/src/a.js"; git -C "$FLUX" commit -qam c2
HASH2=$(tree_hash "$FLUX"); SHA2=$(git -C "$FLUX" rev-parse HEAD)
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=signed" ] && ok "signed" || bad "rc=$RC result=$RESULT"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'j.signed.seq')" = 2 ] && ok "seq 2" || bad "seq"
[ "$(listq ".includes('$HASH2')")" = "true" ] && ok "new hash listed" || bad "not listed"
[ "$(listq '.length')" = 3 ] && ok "appended, nothing lost" || bad "length"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH2'].branch")" = "master" ] && ok "own-view branch label" || bad "label"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH2'].derived")" = "true" ] && ok "derived" || bad "derived flag"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.commits['$SHA2']")" = "$HASH2" ] && ok "commits map" || bad "commits map"

# ---------- 4. non-ZelBack commit: same tree hash, state-only, no seq burn ----------
say "4 non-tree commit"
echo 'docs' >> "$FLUX/readme.md"; git -C "$FLUX" commit -qam c3
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=state" ] && ok "state only" || bad "rc=$RC result=$RESULT"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'j.signed.seq')" = 2 ] && ok "no sequence burned" || bad "seq burned"

# ---------- 5. dispatch hint for an orphaned commit ----------
say "5 orphaned dispatch"
git -C "$FLUX" checkout -qb doomed
echo 'delta' > "$FLUX/ZelBack/src/d.js"; git -C "$FLUX" add -A; git -C "$FLUX" commit -qm c4
HASH4=$(tree_hash "$FLUX"); SHA4=$(git -C "$FLUX" rev-parse HEAD)
git -C "$FLUX" checkout -q master; git -C "$FLUX" branch -qD doomed
DISPATCH_COMMIT=$SHA4 DISPATCH_REF=doomed DISPATCH_REF_TYPE=branch bash -c 'cd '"$WORK"' && node scripts/sign-hashlist.js' >"$TMP/out5.txt" 2>"$TMP/last-stderr.txt"; RC=$?
[ "$RC" = 0 ] && [ "$(cat "$TMP/out5.txt")" = "changed=signed" ] && ok "orphan derived via hint" || bad "rc=$RC $(cat "$TMP/out5.txt")"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH4'].branch")" = "doomed" ] && ok "dispatch fallback label" || bad "label"

# ---------- 6. claimed_hash mismatch is a red run that publishes nothing ----------
say "6 claimed mismatch"
echo 'epsilon' > "$FLUX/ZelBack/src/e.js"; git -C "$FLUX" add -A; git -C "$FLUX" commit -qm c5
SHA5=$(git -C "$FLUX" rev-parse HEAD)
BEFORE=$(cat "$WORK/src/hashes/provenance.json")
DISPATCH_COMMIT=$SHA5 DISPATCH_CLAIMED_HASH=00000000000000000000000000000000 bash -c 'cd '"$WORK"' && node scripts/sign-hashlist.js' >/dev/null 2>"$TMP/last-stderr.txt"; RC=$?
grep -q 'environment drift or a hostile dispatch' "$TMP/last-stderr.txt" && [ "$RC" != 0 ] && ok "red run" || bad "rc=$RC"
[ "$(cat "$WORK/src/hashes/provenance.json")" = "$BEFORE" ] && ok "published nothing" || bad "state leaked"

# ---------- 7. correct claimed_hash passes; catches up c5 too ----------
say "7 claimed match"
HASH5=$(tree_hash "$FLUX")
DISPATCH_COMMIT=$SHA5 DISPATCH_CLAIMED_HASH=$HASH5 bash -c 'cd '"$WORK"' && node scripts/sign-hashlist.js' >"$TMP/out7.txt" 2>"$TMP/last-stderr.txt"; RC=$?
[ "$RC" = 0 ] && [ "$(cat "$TMP/out7.txt")" = "changed=signed" ] && [ "$(listq ".includes('$HASH5')")" = "true" ] && ok "derived with matching claim" || bad "rc=$RC"

# ---------- 8. cull through the ledger ----------
say "8 cull"
printf '{\n  "culls": [\n    { "hash": "ffffffffffffffffffffffffffffffff", "reason": "test cull", "date": "2026-08-24" }\n  ]\n}\n' > "$WORK/src/hashes/ledger.json"
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=signed" ] && ok "resigned" || bad "rc=$RC result=$RESULT"
[ "$(listq ".includes('ffffffffffffffffffffffffffffffff')")" = "false" ] && ok "culled entry gone" || bad "still listed"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['ffffffffffffffffffffffffffffffff'] !== undefined")" = "true" ] && ok "cull keeps its audit row" || bad "row lost"

# ---------- 9. duplicate entry in the list is refused ----------
say "9 duplicate refused"
node -e "
const fs=require('fs'); const p='$WORK/src/hashes/hashes.js';
fs.writeFileSync(p, fs.readFileSync(p,'utf8').replace(\"    '$HASH1',\", \"    '$HASH1',\n    '$HASH1',\"));
"
run_signer
[ "$RC" != 0 ] && grep -q 'duplicates' "$TMP/last-stderr.txt" && ok "red on duplicates" || bad "rc=$RC"
node -e "
const fs=require('fs'); const p='$WORK/src/hashes/hashes.js';
fs.writeFileSync(p, fs.readFileSync(p,'utf8').replace(\"    '$HASH1',\n    '$HASH1',\", \"    '$HASH1',\"));
"

# ---------- 10. tag on a known commit annotates without a sequence ----------
say "10 tag annotation"
git -C "$FLUX" tag v1-test "$SHA2"
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=state" ] && ok "state only" || bad "rc=$RC result=$RESULT"
[ "$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH2'].tag")" = "v1-test" ] && ok "row annotated" || bad "tag"

# ---------- 11. annotated tag on a NEW commit derives with tag label ----------
say "11 tagged new commit"
git -C "$FLUX" checkout -q master
echo 'zeta' > "$FLUX/ZelBack/src/z.js"; git -C "$FLUX" add -A; git -C "$FLUX" commit -qm c6
git -C "$FLUX" tag -a v2-test -m 'release'
HASH6=$(tree_hash "$FLUX")
run_signer
[ "$RC" = 0 ] && [ "$RESULT" = "changed=signed" ] && ok "signed" || bad "rc=$RC result=$RESULT"
TAGLABEL=$(jsonq "$WORK/src/hashes/provenance.json" "j.hashes['$HASH6'].tag || j.hashes['$HASH6'].branch")
[ -n "$TAGLABEL" ] && ok "labelled ($TAGLABEL)" || bad "no label"

# ---------- 12. corrupt provenance is a red run ----------
say "12 corrupt provenance"
cp "$WORK/src/hashes/provenance.json" "$TMP/prov-backup.json"
echo 'not json' > "$WORK/src/hashes/provenance.json"
run_signer
[ "$RC" != 0 ] && ok "red on corrupt provenance" || bad "rc=$RC"
cp "$TMP/prov-backup.json" "$WORK/src/hashes/provenance.json"

# ---------- 13. corrupt ledger is a red run ----------
say "13 corrupt ledger"
cp "$WORK/src/hashes/ledger.json" "$TMP/ledger-backup.json"
echo '{"culls": [{"hash": "short"}]}' > "$WORK/src/hashes/ledger.json"
run_signer
[ "$RC" != 0 ] && grep -q 'ledger cull' "$TMP/last-stderr.txt" && ok "red on bad cull" || bad "rc=$RC"
cp "$TMP/ledger-backup.json" "$WORK/src/hashes/ledger.json"

# ---------- 14. validate.js green on the final state ----------
say "14 validate green"
(cd "$WORK" && node scripts/validate.js 2>"$TMP/validate-out.txt"); RC=$?
[ "$RC" = 0 ] && ok "validate green" || { bad "validate rc=$RC"; cat "$TMP/validate-out.txt"; }

# ---------- 15. validate red when the signed document is wiped ----------
say "15 wiped document"
mv "$WORK/src/hashes/hashlist-signed.json" "$HERE/signed-backup.json"
(cd "$WORK" && node scripts/validate.js 2>"$TMP/validate-out.txt"); RC=$?
[ "$RC" != 0 ] && grep -q 'no signed document' "$TMP/validate-out.txt" && ok "wipe is loud" || bad "rc=$RC"
mv "$HERE/signed-backup.json" "$WORK/src/hashes/hashlist-signed.json"

# ---------- 16. v1 provenance (rows + signed, no refs): bootstrap preserves the sequence ----------
say "16 v1 compatibility"
node -e "
const fs=require('fs'); const p='$WORK/src/hashes/provenance.json';
const j=JSON.parse(fs.readFileSync(p,'utf8'));
delete j.refs; delete j.commits;
Object.values(j.hashes).forEach((row)=>delete row.derived);
fs.writeFileSync(p, JSON.stringify(j,null,2)+'\n');
"
SEQ_BEFORE=$(jsonq "$WORK/src/hashes/provenance.json" 'j.signed.seq')
run_signer
[ "$RC" = 0 ] && ok "v1 record accepted (result=$RESULT)" || bad "rc=$RC"
[ "$(jsonq "$WORK/src/hashes/provenance.json" 'Object.keys(j.refs).length > 0')" = "true" ] && ok "snapshot rebuilt" || bad "no snapshot"
SEQ_AFTER=$(jsonq "$WORK/src/hashes/provenance.json" 'j.signed.seq')
[ "$SEQ_AFTER" -ge "$SEQ_BEFORE" ] && ok "sequence preserved ($SEQ_BEFORE -> $SEQ_AFTER)" || bad "sequence restarted"

# ---------- 17-18. nothing was hashed: the empty-tree hash must never be listed ----------
# The pipeline yields d41d8cd98f00b204e9800998ecf8427e -- the md5 of an empty stream -- whenever
# nothing was hashed. It is a well-formed 32-hex value, so nothing downstream tells it apart from
# a real tree hash, and it would mean "a node whose ZelBack holds no regular files is genuine
# FluxOS". Membership is monotonic, so listing it once costs a cull PR.
#
# The two ways in have DIFFERENT guards, so each case asserts the message it should die on --
# asserting only "the run went red" passes for any reason at all and tests nothing.
EMPTY_HASH=d41d8cd98f00b204e9800998ecf8427e

say "17 ZelBack absent (find errors; caught by pipefail)"
git -C "$FLUX" checkout -q -b nozelback master
git -C "$FLUX" rm -rq ZelBack
git -C "$FLUX" commit -qm "drop ZelBack entirely"
SHA_NOZB=$(git -C "$FLUX" rev-parse HEAD)
BEFORE=$(cat "$WORK/src/hashes/provenance.json")
DISPATCH_COMMIT=$SHA_NOZB run_signer
grep -q 'Command failed' "$TMP/last-stderr.txt" && [ "$RC" != 0 ] \
  && ok "red on the pipeline's own failure" || bad "rc=$RC -- expected a pipefail death, got: $(tail -1 "$TMP/last-stderr.txt")"
[ "$(listq ".includes('$EMPTY_HASH')")" = "false" ] && ok "empty hash not listed" || bad "EMPTY HASH REACHED THE LIST"
[ "$(cat "$WORK/src/hashes/provenance.json")" = "$BEFORE" ] && ok "published nothing" || bad "state leaked"

say "18 ZelBack holds no regular files (find exits 0; pipefail cannot see it)"
# Only symlinks and directories: find -type f matches nothing and exits 0, so the pipeline
# succeeds and returns the empty hash. Git cannot store an empty directory, but it stores a
# symlink (mode 120000) -- this is the reachable shape of "present but nothing to hash".
git -C "$FLUX" checkout -q -b emptyzelback master
git -C "$FLUX" rm -rq ZelBack
mkdir -p "$FLUX/ZelBack/sub"
ln -s /dev/null "$FLUX/ZelBack/link.js"
ln -s /dev/null "$FLUX/ZelBack/sub/deep.js"
git -C "$FLUX" add -A
git -C "$FLUX" commit -qm "ZelBack with no regular files"
SHA_EMPTYZB=$(git -C "$FLUX" rev-parse HEAD)
BEFORE=$(cat "$WORK/src/hashes/provenance.json")
DISPATCH_COMMIT=$SHA_EMPTYZB run_signer
grep -q 'nothing was hashed' "$TMP/last-stderr.txt" && [ "$RC" != 0 ] \
  && ok "red on the empty-hash guard" || bad "rc=$RC -- expected the guard to fire, got: $(tail -1 "$TMP/last-stderr.txt")"
[ "$(listq ".includes('$EMPTY_HASH')")" = "false" ] && ok "empty hash not listed" || bad "EMPTY HASH REACHED THE LIST"
[ "$(cat "$WORK/src/hashes/provenance.json")" = "$BEFORE" ] && ok "published nothing" || bad "state leaked"
git -C "$FLUX" checkout -q master

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
