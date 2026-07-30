"""Scan ingestion + vulnerability lifecycle state machine.

A scan import is idempotent per (asset, vulnerability, port): re-importing the
same file changes nothing but `last_detected`. Lifecycle:

    (absent) --seen--> OPEN --absent in later scan--> CLOSED
                        |  \\--mitigation file----> MITIGATED --seen again--> OPEN (reopened)
                        \\--manual----------------> RISK_ACCEPTED | FALSE_POSITIVE

Auto-closure is scoped to assets present in the scan being imported, so
importing a single department's scan never closes another department's findings.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from typing import Any

from . import db, parsing
from .classify import Classifier, os_family

OPEN_STATES = ("open", "reopened")
ACTIVE_STATES = ("open", "reopened", "mitigated")
STATUSES = ["open", "mitigated", "closed", "risk_accepted", "false_positive"]

CRITICALITY_WEIGHT = {"critical": 1.35, "high": 1.2, "medium": 1.0, "low": 0.85, "": 1.0}


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def today() -> dt.date:
    return dt.date.today()


def d(s: str | None) -> dt.date | None:
    if not s:
        return None
    try:
        return dt.date.fromisoformat(str(s)[:10])
    except ValueError:
        return None


def sha(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:16]


def sla_map(conn: sqlite3.Connection) -> dict[str, int]:
    return {r["severity"]: r["days"] for r in conn.execute("SELECT severity, days FROM sla_policy")}


def risk_score(sev_rank: int, cvss: float | None, exploit: int, criticality: str | None) -> float:
    base = (cvss if cvss else [0.5, 2.5, 5.5, 8.0, 9.5][max(0, min(4, sev_rank))]) * 10
    if exploit:
        base *= 1.25
    base *= CRITICALITY_WEIGHT.get((criticality or "").strip().lower(), 1.0)
    return round(min(100.0, base), 1)


# --------------------------------------------------------------------------
# Row normalisation
# --------------------------------------------------------------------------
def normalize_row(row: dict, mapping: dict[str, str], qualys: bool = False) -> dict:
    out: dict[str, Any] = {}
    for header, field in mapping.items():
        val = row.get(header)
        if isinstance(val, str):
            val = val.strip()
        out[field] = val
    for k in ("hostname", "ip_address", "title", "plugin_id"):
        out.setdefault(k, None)

    out["cvss_score"] = parsing.to_float(out.get("cvss_score"))
    out["severity"] = parsing.norm_severity(out.get("severity"), out.get("cvss_score"), qualys)
    out["severity_rank"] = parsing.SEVERITY_RANK[out["severity"]]
    out["exploit_available"] = parsing.to_bool(out.get("exploit_available"))
    out["first_detected"] = parsing.to_date(out.get("first_detected"))
    out["last_detected"] = parsing.to_date(out.get("last_detected"))
    out["mitigated_date"] = parsing.to_date(out.get("mitigated_date"))
    out["port"] = str(out.get("port") or "").strip() or "0"
    out["protocol"] = (str(out.get("protocol") or "").strip() or "").lower()
    out["hostname"] = (str(out.get("hostname") or "").strip() or None)
    out["ip_address"] = (str(out.get("ip_address") or "").strip() or None)
    out["title"] = (str(out.get("title") or "").strip() or None)
    return out


def asset_key_of(row: dict) -> str | None:
    host = (row.get("hostname") or "").strip().lower()
    ip = (row.get("ip_address") or "").strip()
    if host and not host.replace(".", "").isdigit():
        return f"h:{host}"
    if ip:
        return f"i:{ip}"
    if host:
        return f"h:{host}"
    return None


def vuln_key_of(row: dict) -> str | None:
    pid = str(row.get("plugin_id") or "").strip()
    title = (row.get("title") or "").strip()
    if pid and pid.lower() not in {"none", "nan", "0"}:
        return f"p:{pid}"
    if title:
        return f"t:{sha(title.lower())}"
    return None


# --------------------------------------------------------------------------
# Importer
# --------------------------------------------------------------------------
class ImportResult(dict):
    pass


def import_scan(
    raw: bytes,
    filename: str,
    kind: str = "scan",
    scan_date: str | None = None,
    scanner: str | None = None,
    name: str | None = None,
    auto_close: bool = True,
    dry_run: bool = False,
    actor: str = "import",
    conn: sqlite3.Connection | None = None,
) -> ImportResult:
    c = conn or db.get_conn()
    headers, rows = parsing.read_any(raw, filename)
    mapping = parsing.build_mapping(headers)
    qualys = parsing.looks_like_qualys(headers)

    if "title" not in mapping.values() and "plugin_id" not in mapping.values():
        raise ValueError(
            "Could not find a vulnerability name/ID column. Recognised headers: "
            + ", ".join(sorted(set(mapping.keys()))) or "none"
        )

    norm = [normalize_row(r, mapping, qualys) for r in rows]
    scan_dt = parsing.to_date(scan_date) or _infer_scan_date(norm)
    stats = {
        "rows_total": len(rows), "rows_imported": 0, "rows_skipped": 0,
        "assets_touched": 0, "findings_new": 0, "findings_updated": 0,
        "findings_reopened": 0, "findings_closed": 0, "unmatched": 0,
    }

    if dry_run:
        preview = []
        clf = Classifier(c)
        for r in norm[:25]:
            cls = clf.classify(
                title=r.get("title") or "", family=r.get("family") or "",
                product=r.get("product") or "", description=r.get("description") or "",
                solution=r.get("solution") or "", port=r.get("port") or "",
                service=r.get("service") or "", os_name=r.get("os_name") or "",
            )
            preview.append({
                "hostname": r.get("hostname"), "ip": r.get("ip_address"),
                "title": r.get("title"), "severity": r.get("severity"),
                "category": cls["category"], "subcategory": cls["subcategory"],
                "confidence": cls["confidence"],
            })
        return ImportResult({
            "dry_run": True, "scan_date": scan_dt, "kind": kind,
            "detected_columns": mapping, "unmapped_columns":
                [h for h in headers if h not in mapping],
            "rows_total": len(rows), "preview": preview,
        })

    cur = c.execute(
        "INSERT INTO scans(name,filename,kind,scanner,scan_date,imported_at,imported_by,"
        "rows_total,status,mapping_json) VALUES(?,?,?,?,?,?,?,?,'running',?)",
        (name or filename, filename, kind, scanner or _guess_scanner(headers), scan_dt,
         now_iso(), actor, len(rows), json.dumps(mapping)),
    )
    scan_id = cur.lastrowid
    c.commit()

    try:
        if kind == "mitigation":
            _apply_mitigation(c, norm, scan_id, scan_dt, stats, actor)
        else:
            _apply_scan(c, norm, scan_id, scan_dt, stats, auto_close, actor)
        c.execute(
            "UPDATE scans SET rows_imported=?, rows_skipped=?, assets_touched=?, findings_new=?, "
            "findings_updated=?, findings_reopened=?, findings_closed=?, status='complete' "
            "WHERE id=?",
            (stats["rows_imported"], stats["rows_skipped"], stats["assets_touched"],
             stats["findings_new"], stats["findings_updated"], stats["findings_reopened"],
             stats["findings_closed"], scan_id),
        )
        c.commit()
    except Exception as exc:  # keep a record of failed imports
        c.execute("UPDATE scans SET status='failed', message=? WHERE id=?", (str(exc)[:500], scan_id))
        c.commit()
        raise

    recompute_aging(c)
    stats.update({"scan_id": scan_id, "scan_date": scan_dt, "kind": kind,
                  "detected_columns": mapping,
                  "unmapped_columns": [h for h in headers if h not in mapping]})
    return ImportResult(stats)


def _infer_scan_date(rows: list[dict]) -> str:
    dates = [r.get("last_detected") for r in rows if r.get("last_detected")]
    return max(dates) if dates else today().isoformat()


def _guess_scanner(headers: list[str]) -> str:
    hs = {parsing.norm_header(h) for h in headers}
    if "qid" in hs:
        return "Qualys"
    if "pluginid" in hs:
        return "Tenable/Nessus"
    if {"vulnerabilityid", "nexposeid"} & hs:
        return "Rapid7"
    if "oid" in hs:
        return "OpenVAS/GVM"
    return "Generic"


def _upsert_asset(c: sqlite3.Connection, r: dict, scan_dt: str, cache: dict) -> int | None:
    key = asset_key_of(r)
    if not key:
        return None
    if key in cache:
        aid = cache[key]
    else:
        row = c.execute("SELECT id, manual_fields FROM assets WHERE asset_key=?", (key,)).fetchone()
        if row:
            aid = row["id"]
        else:
            cur = c.execute(
                "INSERT INTO assets(asset_key,hostname,ip_address,first_seen,last_seen,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (key, r.get("hostname"), r.get("ip_address"), scan_dt, scan_dt,
                 now_iso(), now_iso()),
            )
            aid = cur.lastrowid
        cache[key] = aid

    row = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    locked = set(json.loads(row["manual_fields"] or "[]"))
    updates: dict[str, Any] = {}
    for field in ("hostname", "ip_address", "os_name", "department", "application",
                  "system_owner", "owner_email", "business_unit", "environment",
                  "criticality", "location", "tags"):
        val = r.get(field)
        if val in (None, "", "nan"):
            continue
        if field in locked:  # operator edit wins over scanner data
            continue
        if (row[field] or "") != str(val):
            updates[field] = str(val)
    if r.get("os_name"):
        updates["os_family"] = os_family(str(r["os_name"]))
    first = row["first_seen"] or scan_dt
    updates["first_seen"] = min(first, scan_dt)
    updates["last_seen"] = max(row["last_seen"] or scan_dt, scan_dt)
    updates["updated_at"] = now_iso()
    sets = ", ".join(f"{k}=?" for k in updates)
    c.execute(f"UPDATE assets SET {sets} WHERE id=?", (*updates.values(), aid))
    return aid


def _upsert_vuln(c: sqlite3.Connection, r: dict, clf: Classifier, cache: dict) -> int | None:
    key = vuln_key_of(r)
    if not key:
        return None
    if key in cache:
        vid = cache[key]
        c.execute(
            "UPDATE vulns SET last_seen=?, severity=CASE WHEN ?>COALESCE(severity_rank,-1) THEN ? "
            "ELSE severity END, severity_rank=MAX(COALESCE(severity_rank,0),?) WHERE id=?",
            (r.get("last_detected") or today().isoformat(), r["severity_rank"], r["severity"],
             r["severity_rank"], vid),
        )
        return vid

    row = c.execute("SELECT id FROM vulns WHERE vuln_key=?", (key,)).fetchone()
    cls = clf.classify(
        title=r.get("title") or "", family=r.get("family") or "", product=r.get("product") or "",
        description=r.get("description") or "", solution=r.get("solution") or "",
        port=r.get("port") or "", service=r.get("service") or "", os_name=r.get("os_name") or "",
    )
    if row:
        vid = row["id"]
        c.execute(
            "UPDATE vulns SET title=COALESCE(NULLIF(?,''),title), severity=?, severity_rank=?, "
            "cvss_score=COALESCE(?,cvss_score), cve=COALESCE(NULLIF(?,''),cve), "
            "solution=COALESCE(NULLIF(?,''),solution), category=?, subcategory=?, "
            "classified_by=?, classify_rule=?, classify_confidence=?, "
            "exploit_available=MAX(COALESCE(exploit_available,0),?), last_seen=?, updated_at=? "
            "WHERE id=?",
            (r.get("title") or "", r["severity"], r["severity_rank"], r.get("cvss_score"),
             r.get("cve") or "", r.get("solution") or "", cls["category"], cls["subcategory"],
             cls["classified_by"], cls["rule"], cls["confidence"], r["exploit_available"],
             r.get("last_detected") or today().isoformat(), now_iso(), vid),
        )
    else:
        cur = c.execute(
            "INSERT INTO vulns(vuln_key,plugin_id,title,severity,severity_rank,cvss_score,"
            "cvss_vector,cve,category,subcategory,product,family,description,solution,"
            "exploit_available,classified_by,classify_rule,classify_confidence,first_seen,"
            "last_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, str(r.get("plugin_id") or ""), r.get("title"), r["severity"],
             r["severity_rank"], r.get("cvss_score"), r.get("cvss_vector"), r.get("cve"),
             cls["category"], cls["subcategory"], cls["product"], r.get("family"),
             (r.get("description") or "")[:4000], (r.get("solution") or "")[:4000],
             r["exploit_available"], cls["classified_by"], cls["rule"], cls["confidence"],
             r.get("first_detected") or r.get("last_detected") or today().isoformat(),
             r.get("last_detected") or today().isoformat(), now_iso(), now_iso()),
        )
        vid = cur.lastrowid
    cache[key] = vid
    return vid


def _event(c, finding_id, event_type, frm, to, scan_id, actor, note=""):
    c.execute(
        "INSERT INTO finding_events(finding_id,event_type,from_status,to_status,scan_id,actor,"
        "note,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (finding_id, event_type, frm, to, scan_id, actor, note, now_iso()),
    )


def _apply_scan(c, rows, scan_id, scan_dt, stats, auto_close, actor):
    clf = Classifier(c)
    slas = sla_map(c)
    a_cache: dict[str, int] = {}
    v_cache: dict[str, int] = {}
    seen_findings: set[int] = set()
    seen_assets: set[int] = set()

    for r in rows:
        aid = _upsert_asset(c, r, scan_dt, a_cache)
        vid = _upsert_vuln(c, r, clf, v_cache) if aid else None
        if not aid or not vid:
            stats["rows_skipped"] += 1
            continue
        seen_assets.add(aid)

        fkey = f"{aid}|{vid}|{r['port']}|{r['protocol']}"
        sev, rank = r["severity"], r["severity_rank"]
        sla_days = slas.get(sev, 90)
        first = r.get("first_detected") or scan_dt
        crit = c.execute("SELECT criticality FROM assets WHERE id=?", (aid,)).fetchone()["criticality"]
        rscore = risk_score(rank, r.get("cvss_score"), r["exploit_available"], crit)

        row = c.execute("SELECT * FROM findings WHERE finding_key=?", (fkey,)).fetchone()
        if row is None:
            due = (d(first) + dt.timedelta(days=sla_days)).isoformat() if d(first) else None
            cur = c.execute(
                "INSERT INTO findings(finding_key,asset_id,vuln_id,port,protocol,service,status,"
                "severity,severity_rank,cvss_score,first_detected,last_detected,due_date,sla_days,"
                "first_scan_id,last_scan_id,evidence,risk_score,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fkey, aid, vid, r["port"], r["protocol"], r.get("service"), sev, rank,
                 r.get("cvss_score"), first, scan_dt, due, sla_days, scan_id, scan_id,
                 (r.get("evidence") or r.get("Plugin Output") or "")[:4000] if isinstance(r.get("evidence"), str) else None,
                 rscore, now_iso(), now_iso()),
            )
            fid = cur.lastrowid
            _event(c, fid, "detected", None, "open", scan_id, actor)
            stats["findings_new"] += 1
        else:
            fid = row["id"]
            prev = row["status"]
            if prev in ("mitigated", "closed"):
                c.execute(
                    "UPDATE findings SET status='open', reopened_count=COALESCE(reopened_count,0)+1,"
                    " closed_date=NULL, days_to_close=NULL, last_detected=?, severity=?, "
                    "severity_rank=?, cvss_score=COALESCE(?,cvss_score), risk_score=?, "
                    "last_scan_id=?, updated_at=? WHERE id=?",
                    (scan_dt, sev, rank, r.get("cvss_score"), rscore, scan_id, now_iso(), fid),
                )
                _event(c, fid, "reopened", prev, "open", scan_id, actor,
                       "still present in scan")
                stats["findings_reopened"] += 1
            else:
                c.execute(
                    "UPDATE findings SET last_detected=?, severity=?, severity_rank=?, "
                    "cvss_score=COALESCE(?,cvss_score), risk_score=?, last_scan_id=?, "
                    "updated_at=? WHERE id=?",
                    (scan_dt, sev, rank, r.get("cvss_score"), rscore, scan_id, now_iso(), fid),
                )
                stats["findings_updated"] += 1
        seen_findings.add(fid)
        stats["rows_imported"] += 1

    stats["assets_touched"] = len(seen_assets)

    if auto_close and seen_assets:
        placeholders = ",".join("?" * len(seen_assets))
        candidates = c.execute(
            f"SELECT id, status, first_detected FROM findings WHERE asset_id IN ({placeholders}) "
            f"AND status IN ('open','reopened','mitigated')",
            tuple(seen_assets),
        ).fetchall()
        for row in candidates:
            if row["id"] in seen_findings:
                continue
            fd, sd = d(row["first_detected"]), d(scan_dt)
            dtc = (sd - fd).days if fd and sd else None
            c.execute(
                "UPDATE findings SET status='closed', closed_date=?, days_to_close=?, "
                "updated_at=? WHERE id=?",
                (scan_dt, dtc, now_iso(), row["id"]),
            )
            _event(c, row["id"], "closed", row["status"], "closed", scan_id, actor,
                   "not present in latest scan of this asset")
            stats["findings_closed"] += 1
    c.commit()
    clf.flush_hits()


def _apply_mitigation(c, rows, scan_id, scan_dt, stats, actor):
    """Mitigation/remediation evidence file: flips matched findings to mitigated/closed."""
    for r in rows:
        akey = asset_key_of(r)
        vkey = vuln_key_of(r)
        if not akey or not vkey:
            stats["rows_skipped"] += 1
            continue
        arow = c.execute("SELECT id FROM assets WHERE asset_key=?", (akey,)).fetchone()
        vrow = c.execute("SELECT id FROM vulns WHERE vuln_key=?", (vkey,)).fetchone()
        if not arow or not vrow:
            stats["unmatched"] += 1
            stats["rows_skipped"] += 1
            continue

        target = str(r.get("status") or "mitigated").strip().lower().replace(" ", "_")
        if target in {"fixed", "remediated", "resolved", "patched", "mitigated"}:
            target = "mitigated"
        elif target in {"closed", "verified", "confirmed_fixed"}:
            target = "closed"
        elif target in {"risk_accepted", "accepted", "exception"}:
            target = "risk_accepted"
        elif target in {"false_positive", "fp", "not_applicable"}:
            target = "false_positive"
        else:
            target = "mitigated"

        mdate = r.get("mitigated_date") or scan_dt
        found = c.execute(
            "SELECT id, status, first_detected FROM findings WHERE asset_id=? AND vuln_id=? "
            "AND status IN ('open','reopened','mitigated')",
            (arow["id"], vrow["id"]),
        ).fetchall()
        if not found:
            stats["unmatched"] += 1
            stats["rows_skipped"] += 1
            continue
        for row in found:
            fd, md = d(row["first_detected"]), d(mdate)
            dtc = (md - fd).days if fd and md else None
            c.execute(
                "UPDATE findings SET status=?, mitigated_date=?, "
                "closed_date=CASE WHEN ? IN ('closed','false_positive') THEN ? ELSE closed_date END,"
                " days_to_close=?, mitigation_scan_id=?, "
                "ticket_ref=COALESCE(NULLIF(?,''),ticket_ref), "
                "remediation_owner=COALESCE(NULLIF(?,''),remediation_owner), "
                "notes=COALESCE(NULLIF(?,''),notes), updated_at=? WHERE id=?",
                (target, mdate, target, mdate, dtc, scan_id, str(r.get("ticket_ref") or ""),
                 str(r.get("remediation_owner") or ""), str(r.get("notes") or ""),
                 now_iso(), row["id"]),
            )
            _event(c, row["id"], "mitigation-import", row["status"], target, scan_id, actor,
                   str(r.get("notes") or ""))
            stats["findings_updated"] += 1
        stats["rows_imported"] += 1
    c.commit()


# --------------------------------------------------------------------------
# Aging / SLA recomputation (also run nightly by the scheduler)
# --------------------------------------------------------------------------
def recompute_aging(conn: sqlite3.Connection | None = None, as_of: dt.date | None = None) -> int:
    c = conn or db.get_conn()
    ref = as_of or today()
    slas = sla_map(c)
    rows = c.execute(
        "SELECT id, status, severity, first_detected, mitigated_date, closed_date, due_date, "
        "sla_days FROM findings"
    ).fetchall()
    updates = []
    for r in rows:
        first = d(r["first_detected"])
        sla_days = r["sla_days"] or slas.get(r["severity"], 90)
        due = d(r["due_date"]) or ((first + dt.timedelta(days=sla_days)) if first else None)
        if r["status"] in ("closed", "false_positive"):
            end = d(r["closed_date"]) or d(r["mitigated_date"]) or ref
        elif r["status"] == "mitigated":
            end = d(r["mitigated_date"]) or ref
        else:
            end = ref
        age = (end - first).days if first else 0
        breached = 0
        if due:
            if r["status"] in ("open", "reopened"):
                breached = 1 if ref > due else 0
            elif r["status"] in ("closed", "mitigated"):
                breached = 1 if end > due else 0
        updates.append((max(age, 0), due.isoformat() if due else None, sla_days, breached, r["id"]))
    c.executemany(
        "UPDATE findings SET age_days=?, due_date=?, sla_days=?, sla_breached=? WHERE id=?",
        updates,
    )
    c.execute(
        "UPDATE assets SET open_count = (SELECT COUNT(*) FROM findings f WHERE f.asset_id=assets.id"
        " AND f.status IN ('open','reopened')), risk_score = COALESCE((SELECT ROUND(MAX(risk_score),1)"
        " FROM findings f WHERE f.asset_id=assets.id AND f.status IN ('open','reopened')),0)"
    )
    c.commit()
    return len(updates)
