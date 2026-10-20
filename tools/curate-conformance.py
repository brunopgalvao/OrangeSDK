#!/usr/bin/env python3
"""Selects the committed conformance subset from a full execution-spec-tests
fixture set (spec 07 §4.2).

    tools/curate-conformance.py <fixtures>/state_tests crates/solo-conformance/tests/fixtures/state_tests

For each category (fork directory / EIP directory) it takes up to its quota
of cases, round-robin across the category's fixture files so that every test
function is represented before any gets a second case, skipping cases whose
trimmed JSON exceeds MAX_CASE_BYTES (or the category's own limit). Cases named in ALWAYS are taken first.
Each selected test is trimmed to what the runner reads: the environment,
the chain id, the pre-state and the Osaka expectation (with its post-state),
plus the provenance fields of `_info`. The selection is deterministic: the
same fixture set gives the same files.
"""

import json
import os
import sys

FORK = "Osaka"
MAX_CASE_BYTES = 24_000
# Categories whose every case is larger: their few tests are taken anyway.
MAX_CASE_BYTES_IN = {
    "constantinople/eip145_bitwise_shift": 100_000,
    "frontier/create": 200_000,
}

QUOTAS = {
    "berlin/eip2930_access_list": 25,
    "byzantium/eip198_modexp_precompile": 16,
    "cancun/eip1153_tstore": 30,
    "cancun/eip4844_blobs": 30,
    "cancun/eip5656_mcopy": 25,
    "cancun/eip6780_selfdestruct": 30,
    "cancun/eip7516_blobgasfee": 4,
    "constantinople/eip1014_create2": 24,
    "constantinople/eip145_bitwise_shift": 3,
    "frontier/create": 2,
    "frontier/identity_precompile": 12,
    "frontier/opcodes": 50,
    "frontier/precompiles": 25,
    "homestead/coverage": 1,
    "istanbul/eip1344_chainid": 5,
    "istanbul/eip152_blake2": 20,
    "osaka/eip7594_peerdas": 2,
    "osaka/eip7823_modexp_upper_bounds": 12,
    "osaka/eip7825_transaction_gas_limit_cap": 20,
    "osaka/eip7883_modexp_gas_increase": 25,
    "osaka/eip7939_count_leading_zeros": 30,
    "osaka/eip7951_p256verify_precompiles": 40,
    "prague/eip2537_bls_12_381_precompiles": 30,
    "prague/eip7623_increase_calldata_cost": 30,
    "prague/eip7702_set_code_tx": 5,
    "shanghai/eip3651_warm_coinbase": 8,
    "shanghai/eip3855_push0": 10,
    "shanghai/eip3860_initcode": 20,
}

# Regression cases: the guest's heap must hold what a 2^24-gas transaction keeps live.
ALWAYS = ["test_run_until_out_of_gas["]

INFO_FIELDS = ["hash", "url", "description", "fixture-format"]


def trimmed(test):
    post = test["post"][FORK]
    out = {
        "env": test["env"],
        "pre": test["pre"],
        "post": {FORK: post},
        "_info": {k: test["_info"][k] for k in INFO_FIELDS if k in test.get("_info", {})},
    }
    if "config" in test:
        out["config"] = {"chainid": test["config"].get("chainid", "0x01")}
    return out


def category(name):
    parts = [p for p in name.split("::")[0].split("/") if p != "tests"]
    return "/".join(parts[:2])


def main(src, dst):
    by_category = {}
    for root, _, files in sorted(os.walk(src)):
        for f in sorted(files):
            if not f.endswith(".json"):
                continue
            path = os.path.join(root, f)
            with open(path) as fh:
                data = json.load(fh)
            rel = os.path.relpath(path, src)
            cases = []
            for name in sorted(data):
                if FORK not in data[name]["post"]:
                    continue
                t = trimmed(data[name])
                limit = MAX_CASE_BYTES_IN.get(category(name), MAX_CASE_BYTES)
                if len(json.dumps(t, separators=(",", ":"))) <= limit:
                    cases.append((name, t))
            if cases:
                by_category.setdefault(category(cases[0][0]), []).append((rel, cases))
    selected = {}
    for cat, quota in QUOTAS.items():
        files = by_category.get(cat, [])
        chosen = []
        for rel, cases in files:
            for name, t in cases:
                if any(a in name for a in ALWAYS):
                    chosen.append((rel, name, t))
        queues = [list(cases) for _, cases in files]
        rels = [rel for rel, _ in files]
        while len(chosen) < quota and any(queues):
            for i, q in enumerate(queues):
                if q and len(chosen) < quota:
                    name, t = q.pop(0)
                    if not any(name == c[1] for c in chosen):
                        chosen.append((rels[i], name, t))
        for rel, name, t in chosen:
            selected.setdefault(rel, {})[name] = t
    total = 0
    for rel, tests in sorted(selected.items()):
        out = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            json.dump(tests, fh, separators=(",", ":"), sort_keys=True)
            fh.write("\n")
        total += len(tests)
    print(f"{total} tests in {len(selected)} files")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
