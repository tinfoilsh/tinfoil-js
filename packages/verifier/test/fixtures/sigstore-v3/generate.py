#!/usr/bin/env python3
"""Regenerate the public test bundle with two authentic observer receipts."""
import base64
import copy
import datetime
import json
import pathlib
import subprocess
import sys

corpus = pathlib.Path(sys.argv[1]).resolve()
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=corpus, text=True).strip() == "3444516ca6474d1c7c845b8fa60f2083ddcb918b"
sys.path.insert(0, str(corpus / "fixturegen/v3"))
import sigstore_synth as sig

repo = "test/observer"
digest = "ab" * 32
statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "artifact", "digest": {"sha256": digest}}], "predicateType": "https://example.test/predicate/v1", "predicate": {}}
bundle, root = sig.build_bundle(f"https://github.com/{repo}/.github/workflows/release.yml@refs/tags/v1.0.0", sig._canonical_json(statement))
entry = copy.deepcopy(bundle["verificationMaterial"]["tlogEntries"][0])
sig._SECRETS["rekor"] = 0x6161616161616161616161616161616161616161616161616161616161616161
pub = sig._key("rekor").public_key()
key_id = sig.sha256(sig.spki_der(pub))
body = base64.b64decode(entry["canonicalizedBody"])
first = sig.INTEGRATED_TIME
second = first + 1
entry["logId"]["keyId"] = sig.b64(key_id)
entry["integratedTime"] = str(second)
entry["logIndex"] = "42"  # Global sharded index; proof remains local tree index 0.
signed_entry = sig._canonical_json({"body": entry["canonicalizedBody"], "integratedTime": second, "logID": key_id.hex(), "logIndex": 42})
entry["inclusionPromise"]["signedEntryTimestamp"] = sig.b64(sig._key("rekor").sign(signed_entry, sig.ec.ECDSA(sig.hashes.SHA256())))
entry["inclusionProof"]["checkpoint"]["envelope"] = sig._checkpoint_envelope(sig._rfc6962_leaf_hash(body))
bundle["verificationMaterial"]["tlogEntries"].append(entry)
log = copy.deepcopy(root["tlogs"][0])
log["publicKey"] = sig._public_key_entry(pub, key_id, sig.BASE_TIME - datetime.timedelta(days=1))
log["logId"]["keyId"] = sig.b64(key_id)
root["tlogs"].append(log)
pathlib.Path(__file__).with_name("two-observers.json").write_text(json.dumps({"bundle": bundle, "root": root, "digest": digest, "repo": repo, "first": first, "second": second}, indent=2) + "\n")

# Signed provenance cases isolate identity, SCT and complete-predicate rules.
repo = "team/a.b"
identity = f"https://github.com/{repo}/.github/workflows/release.yml@refs/tags/v1.0.0"
statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "artifact", "digest": {"sha256": digest}}], "predicateType": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1", "predicate": {"snp_measurement": "11" * 48, "tdx_measurement": {"rtmr1": "22" * 48, "rtmr2": "33" * 48}, "vm_shape": {"cpus": 2, "memory_mb": 4096, "gpus": 0, "disks": 1}}}
cases = []
def add_case(name, value, san=identity, accepted=False):
    bundle, root = sig.build_bundle(san, sig._canonical_json(value), source_ref="refs/tags/v1.0.0", source_digest="ab" * 20)
    cases.append({"name": name, "bundle": bundle, "root": root, "accepted": accepted})
add_case("escaped repository positive", statement, accepted=True)
add_case("repository regex metacharacter", statement, identity.replace("a.b", "aXb"))
add_case("workflow SAN suffix", statement, identity + "@attacker")
serialized_sct = sig._serialized_sct
sig._serialized_sct = lambda log_id, signature: serialized_sct(log_id, signature[:-1] + bytes([signature[-1] ^ 1]))
add_case("valid certificate with corrupt SCT signature", statement)
sig._serialized_sct = serialized_sct
missing = copy.deepcopy(statement)
del missing["predicate"]["tdx_measurement"]["rtmr2"]
add_case("missing non-running TDX RTMR2", missing)
for field in ["cpus", "memory_mb", "gpus", "disks"]:
    missing = copy.deepcopy(statement)
    del missing["predicate"]["vm_shape"][field]
    add_case("missing VM shape " + field, missing)
pathlib.Path(__file__).with_name("provenance-boundaries.json").write_text(json.dumps({"repo": repo, "digest": digest, "cases": cases}, indent=2) + "\n")
