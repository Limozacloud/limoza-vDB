from ingest import addcve
from ingest.affected import cpe_norm

RECORD = {
    "cveMetadata": {"cveId": "CVE-2026-99999", "state": "PUBLISHED"},
    "containers": {"cna": {"affected": [
        {"vendor": "acme", "product": "widget", "cpes": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],
         "defaultStatus": "unaffected",
         "versions": [{"version": "1.0", "lessThan": "1.4.2", "status": "affected", "versionType": "semver"},
                      {"version": "2.0", "status": "affected"}]},
        {"vendor": "acme", "product": "no-cpe", "versions": [{"version": "1", "status": "affected"}]},
    ]}},
}


def _patch(monkeypatch):
    monkeypatch.setattr(cpe_norm, "load", lambda conn: None)
    monkeypatch.setattr(cpe_norm, "canonical", lambda cpe: (cpe,))


def test_affected_rows_from_cna_cpe(monkeypatch):
    _patch(monkeypatch)
    rows = addcve.affected_rows(None, RECORD)
    assert len(rows) == 2                                 # the entry without a CPE yields nothing
    by_intro = {r[7]: r for r in rows}                    # COLS[7] = introduced
    assert by_intro["1.0"][8] == "1.4.2"                  # fixed = lessThan
    assert by_intro["2.0"][9] == "2.0"                    # bare version = exact, last_affected
    assert all(r[0] == "CVE-2026-99999" and r[1] == "cpe" for r in rows)


def test_record_without_cpe_gives_no_rows(monkeypatch):
    _patch(monkeypatch)
    rec = {"cveMetadata": {"cveId": "CVE-2026-1", "state": "PUBLISHED"},
           "containers": {"cna": {"affected": [{"vendor": "x", "product": "y", "versions": [{"version": "1", "status": "affected"}]}]}}}
    assert addcve.affected_rows(None, rec) == []


def test_add_many_reports_a_failing_cve_without_raising(monkeypatch):
    import os, urllib.error
    from ingest import addcve
    from ingest.records.cvelistv5 import ingest as cv

    class Conn:
        def rollback(self): pass
        def close(self): pass

    monkeypatch.setenv("POSTGRES_DSN", "x")
    monkeypatch.setattr("ingest.core.db.get_conn", lambda: Conn())
    monkeypatch.setattr(cv, "_assigner_map", lambda c: {})

    def fake_add_one(conn, cid, dsn, amap, fetch):
        if cid == "CVE-2026-2":
            raise urllib.error.HTTPError("u", 404, "nf", {}, None)
        return {"cve_id": cid, "state": "PUBLISHED", "records": 1, "affected": 0}

    monkeypatch.setattr(addcve, "add_one", fake_add_one)
    res = addcve.add_many(["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
    assert [r["cve_id"] for r in res] == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
    assert "error" in res[1] and "404" in res[1]["error"] and "error" not in res[0] and "error" not in res[2]
