"""Filter engine shared by list views, dashboards and exports.

Every dashboard, table and export runs through build_where(), so a filter set
saved on the findings table produces exactly the same population when applied to
the executive view or an exported PPTX.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

BASE_FROM = (
    "FROM findings f "
    "JOIN assets a ON a.id = f.asset_id "
    "JOIN vulns  v ON v.id = f.vuln_id"
)

# filter key -> (sql column, kind)
MULTI_FIELDS: dict[str, str] = {
    "status": "f.status",
    "severity": "f.severity",
    "category": "v.category",
    "subcategory": "v.subcategory",
    "department": "a.department",
    "application": "a.application",
    "system_owner": "a.system_owner",
    "environment": "a.environment",
    "criticality": "a.criticality",
    "os_family": "a.os_family",
    "location": "a.location",
    "business_unit": "a.business_unit",
    "hostname": "a.hostname",
    "remediation_owner": "f.remediation_owner",
}

DATE_FIELDS = {"first_detected", "last_detected", "closed_date", "mitigated_date", "due_date"}

SORTABLE = {
    "severity": "f.severity_rank", "age": "f.age_days", "risk": "f.risk_score",
    "hostname": "a.hostname", "title": "v.title", "status": "f.status",
    "first_detected": "f.first_detected", "last_detected": "f.last_detected",
    "due_date": "f.due_date", "department": "a.department", "application": "a.application",
    "system_owner": "a.system_owner", "category": "v.category", "id": "f.id",
}

GROUP_DIMENSIONS = {
    "department": "a.department",
    "application": "a.application",
    "system_owner": "a.system_owner",
    "environment": "a.environment",
    "category": "v.category",
    "subcategory": "v.subcategory",
    "criticality": "a.criticality",
    "os_family": "a.os_family",
    "location": "a.location",
    "severity": "f.severity",
    "status": "f.status",
    "hostname": "a.hostname",
}

OPEN_STATES = ("open", "reopened")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip() != ""]


def normalize_filters(raw: dict[str, Any]) -> dict[str, Any]:
    """Accept query params or a JSON body and produce a canonical filter dict."""
    f: dict[str, Any] = {}
    for key in MULTI_FIELDS:
        vals = _as_list(raw.get(key))
        if vals:
            f[key] = vals
    for key in ("q", "date_field", "date_from", "date_to", "age_min", "age_max",
                "exploitable", "sla_breached", "has_cve", "scan_id", "confidence_below",
                "include_info"):
        val = raw.get(key)
        if val not in (None, "", []):
            f[key] = val
    return f


def build_where(filters: dict[str, Any] | None) -> tuple[str, list[Any]]:
    filters = normalize_filters(filters or {})
    clauses: list[str] = []
    params: list[Any] = []

    for key, col in MULTI_FIELDS.items():
        vals = filters.get(key)
        if not vals:
            continue
        blank = f" OR COALESCE({col},'')=''" if "(blank)" in vals else ""
        vals = [v for v in vals if v != "(blank)"]
        if vals:
            clauses.append(f"({col} IN ({','.join('?' * len(vals))}){blank})")
            params.extend(vals)
        elif blank:
            clauses.append(f"(COALESCE({col},'')='')")

    if filters.get("q"):
        needle = f"%{str(filters['q']).strip().lower()}%"
        clauses.append(
            "(LOWER(COALESCE(a.hostname,'')) LIKE ? OR LOWER(COALESCE(a.ip_address,'')) LIKE ? "
            "OR LOWER(COALESCE(v.title,'')) LIKE ? OR LOWER(COALESCE(v.cve,'')) LIKE ? "
            "OR LOWER(COALESCE(f.ticket_ref,'')) LIKE ? OR LOWER(COALESCE(v.plugin_id,'')) LIKE ?)"
        )
        params.extend([needle] * 6)

    date_field = filters.get("date_field", "first_detected")
    if date_field not in DATE_FIELDS:
        date_field = "first_detected"
    if filters.get("date_from"):
        clauses.append(f"DATE(f.{date_field}) >= DATE(?)")
        params.append(str(filters["date_from"])[:10])
    if filters.get("date_to"):
        clauses.append(f"DATE(f.{date_field}) <= DATE(?)")
        params.append(str(filters["date_to"])[:10])

    if filters.get("age_min") not in (None, ""):
        clauses.append("f.age_days >= ?")
        params.append(int(filters["age_min"]))
    if filters.get("age_max") not in (None, ""):
        clauses.append("f.age_days <= ?")
        params.append(int(filters["age_max"]))

    if str(filters.get("exploitable", "")).lower() in {"1", "true", "yes"}:
        clauses.append("v.exploit_available = 1")
    if str(filters.get("sla_breached", "")).lower() in {"1", "true", "yes"}:
        clauses.append("f.sla_breached = 1")
    if str(filters.get("has_cve", "")).lower() in {"1", "true", "yes"}:
        clauses.append("COALESCE(v.cve,'') <> ''")
    if not str(filters.get("include_info", "")).lower() in {"1", "true", "yes"}:
        pass  # Info findings are included by default; filter via severity=
    if filters.get("scan_id"):
        clauses.append("(f.first_scan_id = ? OR f.last_scan_id = ? OR f.mitigation_scan_id = ?)")
        sid = int(filters["scan_id"])
        params.extend([sid, sid, sid])
    if filters.get("confidence_below") not in (None, ""):
        clauses.append("COALESCE(v.classify_confidence,0) < ?")
        params.append(float(filters["confidence_below"]))

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


def open_clause(alias: str = "f") -> str:
    return f"{alias}.status IN ('open','reopened')"


def period_bounds(filters: dict[str, Any] | None, default_days: int = 90) -> tuple[str, str]:
    filters = filters or {}
    end = str(filters.get("date_to") or dt.date.today().isoformat())[:10]
    start = str(
        filters.get("date_from")
        or (dt.date.fromisoformat(end) - dt.timedelta(days=default_days)).isoformat()
    )[:10]
    return start, end
