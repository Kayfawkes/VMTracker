"""HTTP API surface: auth, data access, editable columns, dashboards, admin."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import Response as FileResponseRaw

from . import auth, classify, db, exports, filters as flt, ingest, jobs, queries

router = APIRouter(prefix="/api")

EDITABLE_ASSET_FIELDS = [
    "hostname", "ip_address", "os_name", "department", "application", "system_owner",
    "owner_email", "business_unit", "environment", "criticality", "location", "tags", "notes",
]
EDITABLE_FINDING_FIELDS = [
    "status", "severity", "remediation_owner", "ticket_ref", "notes", "due_date",
    "exception_until", "mitigated_date",
]


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def audit(entity: str, entity_id: int, field: str, old: Any, new: Any, actor: str,
          source: str = "ui") -> None:
    db.execute(
        "INSERT INTO audit_log(entity,entity_id,field,old_value,new_value,actor,source,created_at)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (entity, entity_id, field, None if old is None else str(old),
         None if new is None else str(new), actor, source, now_iso()),
    )


async def filters_from_request(request: Request) -> dict:
    """Filters may arrive as repeated query params or as a JSON body."""
    raw: dict[str, Any] = {}
    for key in set(request.query_params.keys()):
        values = request.query_params.getlist(key)
        raw[key] = values if len(values) > 1 else values[0]
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = await request.json()
            if isinstance(body, dict):
                raw.update(body.get("filters", body))
        except Exception:
            pass
    return flt.normalize_filters(raw)


# ==========================================================================
# Authentication
# ==========================================================================
@router.post("/auth/login")
def login(response: Response, payload: dict = Body(...)):
    result = auth.login(str(payload.get("username", "")), str(payload.get("password", "")),
                        client=str(payload.get("client", "")))
    response.set_cookie(auth.SESSION_COOKIE, result["token"], httponly=True, samesite="lax",
                        max_age=auth.SESSION_HOURS * 3600, path="/")
    return result


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(auth.SESSION_COOKIE) or request.headers.get("x-vmt-token")
    if token:
        auth.logout(token)
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(user: dict = Depends(auth.current_user)):
    return user


@router.post("/auth/password")
def change_password(payload: dict = Body(...), user: dict = Depends(auth.current_user)):
    row = db.q1("SELECT * FROM users WHERE id=?", (user["id"],))
    if not auth.verify_password(str(payload.get("current_password", "")),
                                row["password_hash"], row["salt"]):
        raise HTTPException(400, "Current password is incorrect")
    try:
        auth.set_password(user["id"], str(payload.get("new_password", "")))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@router.get("/users")
def list_users(user: dict = Depends(auth.require("admin"))):
    return db.q("SELECT id,username,full_name,email,role,is_active,must_change,created_at,"
                "last_login FROM users ORDER BY username")


@router.post("/users")
def add_user(payload: dict = Body(...), user: dict = Depends(auth.require("admin"))):
    try:
        uid = auth.create_user(
            str(payload.get("username", "")), str(payload.get("password", "")),
            role=str(payload.get("role", "viewer")), full_name=str(payload.get("full_name", "")),
            email=str(payload.get("email", "")), must_change=1,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(409, "That username already exists")
    audit("user", uid, "created", None, payload.get("username"), user["username"])
    return db.q1("SELECT id,username,role,full_name,email,is_active FROM users WHERE id=?", (uid,))


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: dict = Body(...),
                user: dict = Depends(auth.require("admin"))):
    row = db.q1("SELECT * FROM users WHERE id=?", (user_id,))
    if not row:
        raise HTTPException(404, "User not found")
    for field in ("full_name", "email", "role", "is_active"):
        if field in payload:
            if field == "role" and payload[field] not in auth.ROLES:
                raise HTTPException(400, f"role must be one of {auth.ROLES}")
            if field == "is_active" and user_id == user["id"] and not payload[field]:
                raise HTTPException(400, "You cannot deactivate your own account")
            db.execute(f"UPDATE users SET {field}=? WHERE id=?", (payload[field], user_id))
            audit("user", user_id, field, row[field], payload[field], user["username"])
    if payload.get("password"):
        try:
            auth.set_password(user_id, str(payload["password"]))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        db.execute("UPDATE users SET must_change=1 WHERE id=?", (user_id,))
        audit("user", user_id, "password", None, "reset", user["username"])
    return db.q1("SELECT id,username,role,full_name,email,is_active FROM users WHERE id=?",
                 (user_id,))


# ==========================================================================
# Findings & assets
# ==========================================================================
@router.get("/findings")
async def get_findings(request: Request, sort: str = "severity", direction: str = "desc",
                       page: int = 1, page_size: int = 100,
                       user: dict = Depends(auth.current_user)):
    f = await filters_from_request(request)
    return queries.findings_page(f, sort, direction, page, page_size)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, user: dict = Depends(auth.current_user)):
    row = db.q1(f"SELECT {queries.FINDING_COLUMNS} {flt.BASE_FROM} WHERE f.id=?", (finding_id,))
    if not row:
        raise HTTPException(404, "Finding not found")
    row["events"] = db.q("SELECT * FROM finding_events WHERE finding_id=? ORDER BY id DESC",
                         (finding_id,))
    row["audit"] = db.q("SELECT * FROM audit_log WHERE entity='finding' AND entity_id=? "
                        "ORDER BY id DESC LIMIT 50", (finding_id,))
    return row


@router.patch("/findings/{finding_id}")
def patch_finding(finding_id: int, payload: dict = Body(...),
                  user: dict = Depends(auth.require("analyst"))):
    row = db.q1("SELECT * FROM findings WHERE id=?", (finding_id,))
    if not row:
        raise HTTPException(404, "Finding not found")
    changed = _apply_finding_edit(finding_id, row, payload, user["username"])
    return {"id": finding_id, "changed": changed,
            "finding": db.q1(f"SELECT {queries.FINDING_COLUMNS} {flt.BASE_FROM} WHERE f.id=?",
                             (finding_id,))}


def _apply_finding_edit(finding_id: int, row: dict, payload: dict, actor: str) -> list[str]:
    changed = []
    for field, value in payload.items():
        if field not in EDITABLE_FINDING_FIELDS:
            continue
        old = row.get(field)
        if field == "status":
            if value not in ingest.STATUSES + ["reopened"]:
                raise HTTPException(400, f"status must be one of {ingest.STATUSES}")
            extra: dict[str, Any] = {}
            today = dt.date.today().isoformat()
            if value == "mitigated":
                extra["mitigated_date"] = payload.get("mitigated_date") or today
            elif value in ("closed", "false_positive"):
                extra["closed_date"] = payload.get("closed_date") or today
                first = row.get("first_detected")
                if first:
                    extra["days_to_close"] = (
                        dt.date.fromisoformat(today) - dt.date.fromisoformat(first[:10])).days
            elif value in ("open", "reopened"):
                extra["closed_date"] = None
                extra["mitigated_date"] = None
            sets = ", ".join(f"{k}=?" for k in extra)
            sql = "UPDATE findings SET status=?" + (f", {sets}" if sets else "") + \
                  ", updated_at=? WHERE id=?"
            db.execute(sql, (value, *extra.values(), now_iso(), finding_id))
            db.execute(
                "INSERT INTO finding_events(finding_id,event_type,from_status,to_status,actor,"
                "note,created_at) VALUES(?,?,?,?,?,?,?)",
                (finding_id, "manual-update", old, value, actor,
                 str(payload.get("notes") or "")[:500], now_iso()),
            )
        else:
            db.execute(f"UPDATE findings SET {field}=?, updated_at=? WHERE id=?",
                       (value, now_iso(), finding_id))
        if str(old) != str(value):
            audit("finding", finding_id, field, old, value, actor)
            changed.append(field)
    ingest.recompute_aging()
    return changed


@router.post("/findings/bulk")
async def bulk_update(request: Request, user: dict = Depends(auth.require("analyst"))):
    body = await request.json()
    fields = body.get("fields") or {}
    ids = body.get("ids")
    if not fields:
        raise HTTPException(400, "No fields supplied")
    if not ids:
        f = flt.normalize_filters(body.get("filters") or {})
        where, params = flt.build_where(f)
        ids = [r["id"] for r in db.q(f"SELECT f.id {flt.BASE_FROM}{where}", params)]
    updated = 0
    for fid in ids:
        row = db.q1("SELECT * FROM findings WHERE id=?", (fid,))
        if row:
            _apply_finding_edit(fid, row, fields, user["username"])
            updated += 1
    return {"updated": updated, "fields": list(fields.keys())}


@router.get("/assets")
async def get_assets(request: Request, user: dict = Depends(auth.current_user)):
    f = await filters_from_request(request)
    where, params = flt.build_where(f)
    return db.q(
        f"SELECT a.*, COUNT(f.id) findings, "
        f"SUM(CASE WHEN f.status IN ('open','reopened') THEN 1 ELSE 0 END) open_findings, "
        f"SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank>=3 THEN 1 ELSE 0 END) "
        f"open_high {flt.BASE_FROM}{where} GROUP BY a.id ORDER BY open_high DESC, a.hostname",
        params)


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: int, payload: dict = Body(...),
                user: dict = Depends(auth.require("analyst"))):
    row = db.q1("SELECT * FROM assets WHERE id=?", (asset_id,))
    if not row:
        raise HTTPException(404, "Asset not found")
    locked = set(json.loads(row.get("manual_fields") or "[]"))
    changed = []
    for field, value in payload.items():
        if field not in EDITABLE_ASSET_FIELDS:
            continue
        old = row.get(field)
        if str(old or "") == str(value or ""):
            continue
        db.execute(f"UPDATE assets SET {field}=?, updated_at=? WHERE id=?",
                   (value, now_iso(), asset_id))
        locked.add(field)  # pin against future scan overwrites
        audit("asset", asset_id, field, old, value, user["username"])
        changed.append(field)
    if changed:
        db.execute("UPDATE assets SET manual_fields=? WHERE id=?",
                   (json.dumps(sorted(locked)), asset_id))
        if "os_name" in changed:
            db.execute("UPDATE assets SET os_family=? WHERE id=?",
                       (classify.os_family(payload.get("os_name")), asset_id))
    return {"id": asset_id, "changed": changed,
            "asset": db.q1("SELECT * FROM assets WHERE id=?", (asset_id,))}


@router.post("/assets/bulk")
async def bulk_assets(request: Request, user: dict = Depends(auth.require("analyst"))):
    """Bulk ownership assignment, e.g. tag every host matching a filter to a department."""
    body = await request.json()
    fields = {k: v for k, v in (body.get("fields") or {}).items()
              if k in EDITABLE_ASSET_FIELDS}
    ids = body.get("ids")
    if not fields:
        raise HTTPException(400, "No editable fields supplied")
    if not ids:
        f = flt.normalize_filters(body.get("filters") or {})
        where, params = flt.build_where(f)
        ids = [r["asset_id"] for r in
               db.q(f"SELECT DISTINCT a.id AS asset_id {flt.BASE_FROM}{where}", params)]
    for aid in ids:
        patch_asset(aid, fields, user)
    return {"updated": len(ids), "fields": list(fields.keys())}


@router.get("/assets/{asset_id}/unlock/{field}")
def unlock_asset_field(asset_id: int, field: str,
                       user: dict = Depends(auth.require("analyst"))):
    """Release a manual override so scanner data can update the field again."""
    row = db.q1("SELECT manual_fields FROM assets WHERE id=?", (asset_id,))
    if not row:
        raise HTTPException(404, "Asset not found")
    locked = [x for x in json.loads(row["manual_fields"] or "[]") if x != field]
    db.execute("UPDATE assets SET manual_fields=? WHERE id=?", (json.dumps(locked), asset_id))
    return {"asset_id": asset_id, "manual_fields": locked}


# ==========================================================================
# Dashboards
# ==========================================================================
@router.get("/dashboard/executive")
async def dash_executive(request: Request, user: dict = Depends(auth.current_user)):
    return queries.executive(await filters_from_request(request))


@router.get("/dashboard/kpis")
async def dash_kpis(request: Request, user: dict = Depends(auth.current_user)):
    return queries.kpis(await filters_from_request(request))


@router.get("/dashboard/group/{dimension}")
async def dash_group(dimension: str, request: Request, limit: int = 200,
                     user: dict = Depends(auth.current_user)):
    f = await filters_from_request(request)
    try:
        return {
            "dimension": dimension,
            "kpis": queries.kpis(f),
            "rows": queries.group_summary(dimension, f, limit=limit),
            "matrix": queries.group_by_type_matrix(f, dimension),
            "aging": queries.aging_buckets(f, group_by=dimension),
            "severity": queries.severity_breakdown(f),
            "trend": queries.trend(f),
            "top_vulnerabilities": queries.top_vulnerabilities(f),
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/dashboard/trend")
async def dash_trend(request: Request, buckets: int = 12,
                     user: dict = Depends(auth.current_user)):
    return queries.trend(await filters_from_request(request), buckets=buckets)


@router.get("/dashboard/sla")
async def dash_sla(request: Request, user: dict = Depends(auth.current_user)):
    return queries.sla_performance(await filters_from_request(request))


@router.get("/filters/options")
def options(user: dict = Depends(auth.current_user)):
    return queries.filter_options()


# ==========================================================================
# Scans / import
# ==========================================================================
@router.get("/scans")
def list_scans(user: dict = Depends(auth.current_user)):
    return db.q("SELECT * FROM scans ORDER BY id DESC LIMIT 200")


@router.post("/scans/import")
async def import_file(
    file: UploadFile = File(...),
    kind: str = Form("scan"),
    scan_date: str | None = Form(None),
    name: str | None = Form(None),
    scanner: str | None = Form(None),
    auto_close: bool = Form(True),
    dry_run: bool = Form(False),
    user: dict = Depends(auth.require("analyst")),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Uploaded file is empty")
    try:
        result = ingest.import_scan(raw, file.filename or "upload.csv", kind=kind,
                                    scan_date=scan_date, scanner=scanner, name=name,
                                    auto_close=auto_close, dry_run=dry_run,
                                    actor=user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return result


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, user: dict = Depends(auth.require("admin"))):
    """Remove the scan record only; findings history is preserved deliberately."""
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    audit("scan", scan_id, "deleted", None, None, user["username"])
    return {"deleted": scan_id}


# ==========================================================================
# Admin: SLA policy, classification rules, saved views
# ==========================================================================
@router.get("/sla")
def get_sla(user: dict = Depends(auth.current_user)):
    return db.q("SELECT severity, days FROM sla_policy ORDER BY days")


@router.put("/sla")
def put_sla(payload: dict = Body(...), user: dict = Depends(auth.require("admin"))):
    """Operator-defined remediation targets per severity; drives every SLA metric."""
    items = payload.get("policy", payload)
    for severity, days in items.items():
        if severity not in queries.SEV_ORDER:
            raise HTTPException(400, f"unknown severity '{severity}'")
        try:
            days_i = int(days)
        except (TypeError, ValueError):
            raise HTTPException(400, f"SLA days for {severity} must be a whole number")
        if days_i < 1 or days_i > 3650:
            raise HTTPException(400, "SLA days must be between 1 and 3650")
        old = db.q1("SELECT days FROM sla_policy WHERE severity=?", (severity,))
        db.execute("INSERT INTO sla_policy(severity,days) VALUES(?,?) "
                   "ON CONFLICT(severity) DO UPDATE SET days=excluded.days", (severity, days_i))
        audit("sla", 0, severity, old["days"] if old else None, days_i, user["username"])
    db.execute("UPDATE findings SET sla_days=NULL, due_date=NULL")  # force recompute
    ingest.recompute_aging()
    return db.q("SELECT severity, days FROM sla_policy ORDER BY days")


@router.get("/rules")
def get_rules(user: dict = Depends(auth.current_user)):
    return db.q("SELECT * FROM class_rules ORDER BY priority, id")


@router.post("/rules")
def add_rule(payload: dict = Body(...), user: dict = Depends(auth.require("admin"))):
    import re as _re
    try:
        _re.compile(payload.get("pattern", ""))
    except _re.error as exc:
        raise HTTPException(400, f"Invalid regular expression: {exc}")
    if payload.get("category") not in classify.CATEGORIES:
        raise HTTPException(400, f"category must be one of {classify.CATEGORIES}")
    cur = db.execute(
        "INSERT INTO class_rules(name,priority,field,pattern,category,subcategory,product,"
        "confidence,enabled,builtin,created_at,updated_at) VALUES(?,?,'haystack',?,?,?,?,?,?,0,?,?)",
        (payload.get("name", "custom rule"), int(payload.get("priority", 5)),
         payload["pattern"], payload["category"], payload.get("subcategory", ""),
         payload.get("product", ""), float(payload.get("confidence", 0.95)),
         1 if payload.get("enabled", True) else 0, now_iso(), now_iso()),
    )
    return db.q1("SELECT * FROM class_rules WHERE id=?", (cur.lastrowid,))


@router.patch("/rules/{rule_id}")
def patch_rule(rule_id: int, payload: dict = Body(...),
               user: dict = Depends(auth.require("admin"))):
    row = db.q1("SELECT * FROM class_rules WHERE id=?", (rule_id,))
    if not row:
        raise HTTPException(404, "Rule not found")
    for field in ("name", "priority", "pattern", "category", "subcategory", "product",
                  "confidence", "enabled"):
        if field in payload:
            db.execute(f"UPDATE class_rules SET {field}=?, updated_at=? WHERE id=?",
                       (payload[field], now_iso(), rule_id))
            audit("rule", rule_id, field, row[field], payload[field], user["username"])
    return db.q1("SELECT * FROM class_rules WHERE id=?", (rule_id,))


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, user: dict = Depends(auth.require("admin"))):
    row = db.q1("SELECT builtin FROM class_rules WHERE id=?", (rule_id,))
    if not row:
        raise HTTPException(404, "Rule not found")
    if row["builtin"]:
        db.execute("UPDATE class_rules SET enabled=0 WHERE id=?", (rule_id,))
        return {"disabled": rule_id, "note": "built-in rules are disabled rather than deleted"}
    db.execute("DELETE FROM class_rules WHERE id=?", (rule_id,))
    return {"deleted": rule_id}


@router.post("/rules/reclassify")
def reclassify(user: dict = Depends(auth.require("admin"))):
    n = classify.reclassify_all()
    return {"reclassified": n}


@router.post("/rules/test")
def test_rule(payload: dict = Body(...), user: dict = Depends(auth.require("analyst"))):
    clf = classify.Classifier()
    return clf.classify(title=str(payload.get("title", "")), family=str(payload.get("family", "")),
                        product=str(payload.get("product", "")), port=str(payload.get("port", "")),
                        service=str(payload.get("service", "")))


@router.get("/views")
def list_views(user: dict = Depends(auth.current_user)):
    return db.q("SELECT * FROM saved_views ORDER BY name")


@router.post("/views")
def save_view(payload: dict = Body(...), user: dict = Depends(auth.require("analyst"))):
    name = str(payload.get("name", "")).strip()
    if not name:
        raise HTTPException(400, "A view name is required")
    db.execute("INSERT INTO saved_views(name,scope,filters,created_at) VALUES(?,?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET filters=excluded.filters, scope=excluded.scope",
               (name, str(payload.get("scope", "findings")),
                json.dumps(payload.get("filters") or {}), now_iso()))
    return db.q1("SELECT * FROM saved_views WHERE name=?", (name,))


@router.delete("/views/{view_id}")
def delete_view(view_id: int, user: dict = Depends(auth.require("analyst"))):
    db.execute("DELETE FROM saved_views WHERE id=?", (view_id,))
    return {"deleted": view_id}


@router.get("/audit")
def get_audit(entity: str | None = None, limit: int = Query(200, le=2000),
              user: dict = Depends(auth.current_user)):
    if entity:
        return db.q("SELECT * FROM audit_log WHERE entity=? ORDER BY id DESC LIMIT ?",
                    (entity, limit))
    return db.q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


# ==========================================================================
# Exports
# ==========================================================================
@router.api_route("/export/{fmt}", methods=["GET", "POST"])
async def export_view(fmt: str, request: Request, scope: str = "executive",
                      include_detail: bool = True, user: dict = Depends(auth.current_user)):
    """Export the current filtered view as csv, xlsx, pdf or pptx."""
    f = await filters_from_request(request)
    try:
        payload, filename, media = exports.export(fmt, f, scope=scope,
                                                  include_detail=include_detail)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    audit("export", 0, fmt, None, json.dumps(f)[:400], user["username"], source="export")
    return FileResponseRaw(
        content=payload, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "X-VMT-Filename": filename},
    )


# ==========================================================================
# Scheduler / system
# ==========================================================================
@router.get("/system/jobs")
def system_jobs(user: dict = Depends(auth.require("admin"))):
    return jobs.status()


@router.post("/system/jobs/{job_id}/run")
def run_job_now(job_id: str, user: dict = Depends(auth.require("admin"))):
    fn = {"aging": jobs.job_aging, "sessions": jobs.job_sessions,
          "watch": jobs.job_watch, "vacuum": jobs.job_vacuum}.get(job_id)
    if not fn:
        raise HTTPException(404, "No such job")
    jobs.run_job(job_id, fn)
    return db.q1("SELECT * FROM job_runs WHERE job=? ORDER BY id DESC LIMIT 1", (job_id,))


@router.get("/system/summary")
def system_summary(user: dict = Depends(auth.current_user)):
    counts = db.q1("SELECT (SELECT COUNT(*) FROM findings) findings, "
                   "(SELECT COUNT(*) FROM assets) assets, (SELECT COUNT(*) FROM vulns) vulns, "
                   "(SELECT COUNT(*) FROM scans) scans, "
                   "(SELECT COUNT(*) FROM class_rules WHERE enabled=1) rules")
    last = db.q1("SELECT name, scan_date, imported_at, kind FROM scans "
                 "WHERE status='complete' ORDER BY id DESC LIMIT 1")
    return {"counts": counts, "last_scan": last,
            "unclassified": db.q1("SELECT COUNT(*) n FROM vulns WHERE category='Other'")["n"]}
