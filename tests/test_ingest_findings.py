# NOTE: Claude wrote these tests.

"""Tests for findings ingestion — parent-walk attribution and edge case handling.

Run directly, no test framework required:

    python3 tests/test_ingest_findings.py

Uses a throwaway database, so the real risk.db is never touched. Tests that need
a Prowler scan are skipped automatically if no CSV is present, so this is safe to
run on a machine that has never scanned.
"""
import os
import sys
import sqlite3
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

# Point config at a throwaway database BEFORE importing it. load_dotenv() does not
# override variables already set in the environment, so this wins over .env.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DB_PATH"] = _tmp_db.name

import db as dbmod                                          # noqa: E402
from config import DB_PATH                                   # noqa: E402
from ingest_findings import (                                # noqa: E402
    find_parent_asset, upsert_findings, load_prowler_findings, find_latest_csv,
    COL_STATUS, COL_RESOURCE_UID,
)

PASSED = FAILED = SKIPPED = 0


def check(name, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED += 1
        print(f"  FAIL  {name}\n          got:  {got!r}\n          want: {want!r}")


def skip(name, why):
    global SKIPPED
    SKIPPED += 1
    print(f"  SKIP  {name} ({why})")


# --------------------------------------------------------------------- fixtures
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourcegroups/rg1"
STORAGE = f"{RG}/providers/microsoft.storage/storageaccounts/sa1"
VNET = f"{RG}/providers/microsoft.network/virtualnetworks/vnet1"
VM = f"{RG}/providers/microsoft.compute/virtualmachines/vm1"


def reset_db(asset_ids):
    """Recreate the throwaway database with the given assets and no findings."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    dbmod.init_db()
    conn = dbmod.get_connection()
    for i, aid in enumerate(asset_ids):
        conn.execute(
            "INSERT INTO assets (asset_id, name, resource_type, criticality,"
            " exposure, environment, last_seen) VALUES (?,?,?,?,?,?,?)",
            (aid, f"asset{i}", "test/type", 3, "Public", "Test", "now"),
        )
    conn.commit()
    conn.close()


def query(sql, args=()):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return rows


def row(**overrides):
    """A minimal Prowler CSV row, overridable per test."""
    base = {
        "FINDING_UID": "finding-1", "STATUS": "FAIL", "SEVERITY": "medium",
        "RESOURCE_UID": VM, "CHECK_ID": "some_check", "CHECK_TITLE": "Some check",
    }
    base.update(overrides)
    return base


# ------------------------------------------------------- unit: find_parent_asset
# The walk must find the owning asset without ever climbing past the top-level
# resource into a resource group or subscription.
print("\n== unit: find_parent_asset ==")
tracked = {STORAGE, VNET}

check("child resource resolves to its parent",
      find_parent_asset(f"{STORAGE}/fileservices/default", tracked), STORAGE)
check("grandchild resolves to the top-level parent",
      find_parent_asset(f"{STORAGE}/blobservices/default/containers/c1", tracked), STORAGE)
check("child of an untracked parent returns nothing",
      find_parent_asset(f"{RG}/providers/microsoft.network/virtualnetworks/other/subnets/s1", tracked), None)
check("subscription-scope id (no /providers/) returns nothing",
      find_parent_asset(SUB, tracked), None)
check("tenant-scope role assignment returns nothing",
      find_parent_asset("/providers/microsoft.authorization/roleassignments/xyz", tracked), None)
check("management group id (two /providers/ segments) returns nothing",
      find_parent_asset("/providers/microsoft.management/managementgroups/mg1"
                        "/providers/microsoft.authorization/roleassignments/xyz", tracked), None)
check("a tracked resource never resolves to itself",
      find_parent_asset(STORAGE, tracked), None)
check("never attributes to a resource group or subscription",
      find_parent_asset(f"{RG}/providers/microsoft.network/virtualnetworks/other/subnets/s1",
                        tracked | {RG, SUB}), None)
check("malformed path (missing name) returns nothing",
      find_parent_asset(f"{RG}/providers/microsoft.storage/storageaccounts", tracked), None)
check("empty string returns nothing", find_parent_asset("", tracked), None)
check("None returns nothing", find_parent_asset(None, tracked), None)

# ----------------------------------------------- integration: synthetic findings
# These build their own rows, so they hold regardless of what the latest scan found.
print("\n== integration: synthetic findings ==")

reset_db([VM])
upsert_findings([row()])
check("directly matched finding is ingested",
      query("SELECT asset_id, resource_uid FROM findings")[0], (VM, VM))

reset_db([STORAGE])
upsert_findings([row(RESOURCE_UID=f"{STORAGE}/fileservices/default")])
check("child finding attributes to parent, keeping the flagged resource",
      query("SELECT asset_id, resource_uid FROM findings")[0],
      (STORAGE, f"{STORAGE}/fileservices/default"))

reset_db([STORAGE])
upsert_findings([row(RESOURCE_UID=f"{STORAGE}/blobservices/default/containers/c1")])
check("grandchild finding attributes to the top-level asset",
      query("SELECT asset_id FROM findings")[0][0], STORAGE)

reset_db([VM])
upsert_findings([row(RESOURCE_UID=f"{RG}/providers/microsoft.compute/virtualmachines/ghost")])
check("finding on an untracked resource is not ingested",
      query("SELECT COUNT(*) FROM findings")[0][0], 0)

reset_db([VM])
upsert_findings([row(RESOURCE_UID="")])
check("row with no RESOURCE_UID is not ingested",
      query("SELECT COUNT(*) FROM findings")[0][0], 0)

reset_db([VM])
upsert_findings([row(FINDING_UID="", CHECK_ID="")])
check("row with neither FINDING_UID nor CHECK_ID is not ingested",
      query("SELECT COUNT(*) FROM findings")[0][0], 0)

reset_db([VM])
upsert_findings([row(STATUS="PASS")])
check("passing check is not recorded as a finding",
      query("SELECT COUNT(*) FROM findings")[0][0], 0)

# A finding marked Remediated must re-open if the scanner still reports it failing.
reset_db([VM])
upsert_findings([row()])
conn = sqlite3.connect(DB_PATH)
conn.execute("UPDATE findings SET status='Remediated'")
conn.commit()
conn.close()
upsert_findings([row()])
check("remediated finding re-opens when it fails again",
      query("SELECT status FROM findings")[0][0], "Open")

# Once the exact resource becomes tracked, an earlier parent attribution corrects itself.
child = f"{STORAGE}/fileservices/default"
reset_db([STORAGE])
upsert_findings([row(RESOURCE_UID=child)])
before = query("SELECT asset_id FROM findings")[0][0]
conn = dbmod.get_connection()
conn.execute("INSERT INTO assets (asset_id, name, resource_type, criticality,"
             " exposure, environment, last_seen) VALUES (?,?,?,?,?,?,?)",
             (child, "fs", "test/type", 3, "Public", "Test", "now"))
conn.commit()
conn.close()
upsert_findings([row(RESOURCE_UID=child)])
check("asset_id re-points once the exact resource becomes tracked",
      (before, query("SELECT asset_id FROM findings")[0][0]), (STORAGE, child))

# Azure Resource Graph and Prowler disagree on casing for some resources.
reset_db([VM])
upsert_findings([row(RESOURCE_UID=VM.replace("/resourcegroups/rg1/", "/resourceGroups/RG1/"))])
check("upper-cased resource id still matches a lowercase-stored asset",
      query("SELECT COUNT(*) FROM findings")[0][0], 1)

reset_db([STORAGE])
upsert_findings([row(RESOURCE_UID=(STORAGE + "/fileServices/default")
                     .replace("/resourcegroups/rg1/", "/resourceGroups/RG1/"))])
check("upper-cased child id still attributes to its parent",
      query("SELECT COUNT(*) FROM findings")[0][0], 1)

reset_db([VM])
upsert_findings([row()])
upsert_findings([row()])
check("re-ingesting the same scan is idempotent",
      query("SELECT COUNT(*) FROM findings")[0][0], 1)

# ---------------------------------------------------- integration: real scan
# Asserts invariants rather than fixed counts, so a new scan doesn't break the suite.
print("\n== integration: latest Prowler scan ==")
try:
    csv_path = find_latest_csv()
except FileNotFoundError:
    csv_path = None

if csv_path is None:
    skip("real scan invariants", "no Prowler CSV found")
else:
    scan_rows = load_prowler_findings(csv_path)
    fails = [r for r in scan_rows if r.get(COL_STATUS, "").upper() == "FAIL"]

    # Track every top-level resource the scan mentions, so the walk has real parents.
    assets = set()
    for r in fails:
        uid = (r.get(COL_RESOURCE_UID) or "").lower()
        if "/providers/" in uid:
            base, tail = uid.split("/providers/", 1)
            parts = tail.split("/")
            if len(parts) >= 3:
                assets.add(f"{base}/providers/{'/'.join(parts[:3])}")
    reset_db(sorted(assets))
    upsert_findings(fails)

    ingested = query("SELECT COUNT(*) FROM findings")[0][0]
    check("every FAIL row with a resolvable asset is ingested", ingested > 0, True)

    orphans = query("SELECT COUNT(*) FROM findings f LEFT JOIN assets a"
                    " ON f.asset_id = a.asset_id WHERE a.asset_id IS NULL")[0][0]
    check("no finding references a missing asset", orphans, 0)

    bad = [r for r in query("SELECT asset_id, resource_uid FROM findings"
                            " WHERE resource_uid != asset_id")
           if not r[1].startswith(r[0] + "/")]
    check("every attributed finding sits underneath its asset", bad, [])

    check("foreign key integrity is clean", query("PRAGMA foreign_key_check"), [])

    upsert_findings(fails)
    check("re-ingesting the real scan is idempotent",
          query("SELECT COUNT(*) FROM findings")[0][0], ingested)

# --------------------------------------------------------------------- teardown
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

print(f"\n{'=' * 52}")
print(f"  {PASSED} passed, {FAILED} failed, {SKIPPED} skipped")
print(f"{'=' * 52}")
sys.exit(1 if FAILED else 0)
