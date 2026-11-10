# NOTE:
Claude wrote these tests, after me throwing some edge cases at the ingestion process.

# Tests

No test framework required — run directly:

```bash
python3 tests/test_ingest_findings.py
```

Exits non-zero if anything fails, so it can be wired into CI or a pre-commit hook.

## What's covered

- **`find_parent_asset` (unit).** Azure records some security settings on child
  resources (e.g. `.../storageAccounts/x/fileServices/default`) which never appear
  in the asset inventory. These tests confirm the walk finds the owning asset and,
  critically, never climbs past the top-level resource into a resource group or
  subscription.
- **Ingestion (synthetic rows).** Attribution, `resource_uid` retention, status
  regression, re-pointing once a resource becomes tracked, resource ID casing, and
  idempotency. These build their own rows, so they hold regardless of what the
  latest scan happens to contain.
- **Ingestion (latest real scan).** Asserts invariants rather than fixed counts —
  no orphaned findings, every attributed finding sits underneath its asset, foreign
  key integrity, idempotency. Skipped automatically if no Prowler CSV is present.

## Safety

Tests point `DB_PATH` at a throwaway database before importing `config`, so the
real `risk.db` is never read or written. They make no Azure API calls.
