"""Aggregation queries powering the dashboards.

Every function takes the same filter dict, so any filter the operator sets on the
findings table reshapes the executive view, the group dashboards and the exports
identically.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
from typing import Any

from . import db, filters as flt

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
AGE_BUCKETS = [(0, 30, "0-30"), (31, 60, "31-60"), (61, 90, "61-90"),
               (91, 180, "91-180"), (181, 10**6, "180+")]


def _conn(conn: sqlite3.Connection | None) -> sqlite3.Connection:
    return conn or db.get_conn()


def _rows(sql: str, params, conn=None) -> list[dict]:
    return [dict(r) for r in _conn(conn).execute(sql, params).fetchall()]


def _one(sql: str, params, conn=None) -> dict:
    row = _conn(conn).execute(sql, params).fetchone()
    return dict(row) if row else {}


# --------------------------------------------------------------------------
# Headline KPIs
# --------------------------------------------------------------------------
def kpis(f: dict[str, Any] | None = None, conn=None) -> dict:
    where, params = flt.build_where(f)
    start, end = flt.period_bounds(f)
    base = flt.BASE_FROM + where

    totals = _one(f"""
        SELECT COUNT(*) total,
          SUM(CASE WHEN f.status IN ('open','reopened') THEN 1 ELSE 0 END) open,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=4 THEN 1 ELSE 0 END) open_critical,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=3 THEN 1 ELSE 0 END) open_high,
          SUM(CASE WHEN f.status='mitigated' THEN 1 ELSE 0 END) mitigated,
          SUM(CASE WHEN f.status='closed' THEN 1 ELSE 0 END) closed,
          SUM(CASE WHEN f.status='risk_accepted' THEN 1 ELSE 0 END) risk_accepted,
          SUM(CASE WHEN f.status='false_positive' THEN 1 ELSE 0 END) false_positive,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.sla_breached=1 THEN 1 ELSE 0 END) open_breached,
          SUM(CASE WHEN f.status IN ('open','reopened') AND v.exploit_available=1 THEN 1 ELSE 0 END) open_exploitable,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.reopened_count>0 THEN 1 ELSE 0 END) reopened,
          ROUND(AVG(CASE WHEN f.status IN ('open','reopened') THEN f.age_days END),1) avg_open_age,
          ROUND(AVG(CASE WHEN f.status IN ('open','reopened') THEN f.risk_score END),1) avg_risk,
          COUNT(DISTINCT CASE WHEN f.status IN ('open','reopened') THEN a.id END) affected_assets,
          COUNT(DISTINCT a.id) assets
        {base}""", params, conn)

    remediated = _one(f"""
        SELECT COUNT(*) n, ROUND(AVG(f.days_to_close),1) mttr,
               ROUND(AVG(CASE WHEN f.severity_rank=4 THEN f.days_to_close END),1) mttr_critical,
               ROUND(AVG(CASE WHEN f.severity_rank=3 THEN f.days_to_close END),1) mttr_high,
               SUM(CASE WHEN f.sla_breached=1 THEN 1 ELSE 0 END) breached
        {base}{' AND' if where else ' WHERE'} f.status IN ('closed','mitigated')
          AND DATE(COALESCE(f.closed_date,f.mitigated_date)) BETWEEN DATE(?) AND DATE(?)
        """, [*params, start, end], conn)

    new_in_period = _one(f"""
        SELECT COUNT(*) n {base}{' AND' if where else ' WHERE'}
        DATE(f.first_detected) BETWEEN DATE(?) AND DATE(?)""",
        [*params, start, end], conn)

    open_total = totals.get("open") or 0
    sla_pop = (open_total + (remediated.get("n") or 0)) or 1
    breach_total = (totals.get("open_breached") or 0) + (remediated.get("breached") or 0)

    return {
        "period": {"from": start, "to": end},
        "total": totals.get("total") or 0,
        "open": open_total,
        "open_critical": totals.get("open_critical") or 0,
        "open_high": totals.get("open_high") or 0,
        "open_critical_high": (totals.get("open_critical") or 0) + (totals.get("open_high") or 0),
        "mitigated": totals.get("mitigated") or 0,
        "closed": totals.get("closed") or 0,
        "risk_accepted": totals.get("risk_accepted") or 0,
        "false_positive": totals.get("false_positive") or 0,
        "open_breached": totals.get("open_breached") or 0,
        "open_exploitable": totals.get("open_exploitable") or 0,
        "reopened": totals.get("reopened") or 0,
        "avg_open_age": totals.get("avg_open_age") or 0,
        "avg_risk": totals.get("avg_risk") or 0,
        "affected_assets": totals.get("affected_assets") or 0,
        "assets": totals.get("assets") or 0,
        "remediated_in_period": remediated.get("n") or 0,
        "new_in_period": new_in_period.get("n") or 0,
        "mttr_days": remediated.get("mttr") or 0,
        "mttr_critical": remediated.get("mttr_critical") or 0,
        "mttr_high": remediated.get("mttr_high") or 0,
        "sla_breach_rate": round(100.0 * breach_total / sla_pop, 1),
        "sla_compliance_rate": round(100.0 - (100.0 * breach_total / sla_pop), 1),
    }


def severity_breakdown(f=None, status: str = "open", conn=None) -> list[dict]:
    where, params = flt.build_where(f)
    cond = _status_condition(status, where)
    rows = _rows(f"""
        SELECT f.severity, COUNT(*) n, SUM(f.sla_breached) breached,
               ROUND(AVG(f.age_days)) avg_age, SUM(v.exploit_available) exploitable
        {flt.BASE_FROM}{where}{cond} GROUP BY f.severity""", params, conn)
    index = {r["severity"]: r for r in rows}
    return [
        {"severity": s, "n": (index.get(s, {}).get("n") or 0),
         "breached": index.get(s, {}).get("breached") or 0,
         "avg_age": index.get(s, {}).get("avg_age") or 0,
         "exploitable": index.get(s, {}).get("exploitable") or 0}
        for s in SEV_ORDER
    ]


def _status_condition(status: str, where: str) -> str:
    joiner = " AND" if where else " WHERE"
    if status == "open":
        return f"{joiner} f.status IN ('open','reopened')"
    if status == "active":
        return f"{joiner} f.status IN ('open','reopened','mitigated')"
    if status in ("mitigated", "closed", "risk_accepted", "false_positive"):
        return f"{joiner} f.status = '{status}'"
    return ""


# --------------------------------------------------------------------------
# Group dashboards (department / application / owner / environment / type)
# --------------------------------------------------------------------------
def group_summary(dimension: str, f=None, status: str = "open", limit: int = 200,
                  conn=None) -> list[dict]:
    col = flt.GROUP_DIMENSIONS.get(dimension)
    if not col:
        raise ValueError(f"unknown grouping dimension '{dimension}'")
    where, params = flt.build_where(f)
    start, end = flt.period_bounds(f)

    rows = _rows(f"""
        SELECT COALESCE(NULLIF({col},''),'(unassigned)') AS grp,
          COUNT(*) total,
          SUM(CASE WHEN f.status IN ('open','reopened') THEN 1 ELSE 0 END) open,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=4 THEN 1 ELSE 0 END) critical,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=3 THEN 1 ELSE 0 END) high,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=2 THEN 1 ELSE 0 END) medium,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=1 THEN 1 ELSE 0 END) low,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.severity_rank=0 THEN 1 ELSE 0 END) info,
          SUM(CASE WHEN f.status='mitigated' THEN 1 ELSE 0 END) mitigated,
          SUM(CASE WHEN f.status='closed' THEN 1 ELSE 0 END) closed,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.sla_breached=1 THEN 1 ELSE 0 END) breached,
          SUM(CASE WHEN f.status IN ('open','reopened') AND v.exploit_available=1 THEN 1 ELSE 0 END) exploitable,
          ROUND(AVG(CASE WHEN f.status IN ('open','reopened') THEN f.age_days END)) avg_age,
          MAX(CASE WHEN f.status IN ('open','reopened') THEN f.age_days END) max_age,
          ROUND(AVG(CASE WHEN f.status IN ('closed','mitigated') AND
                DATE(COALESCE(f.closed_date,f.mitigated_date)) BETWEEN DATE(?) AND DATE(?)
                THEN f.days_to_close END),1) mttr,
          ROUND(SUM(CASE WHEN f.status IN ('open','reopened') THEN f.risk_score ELSE 0 END),0) risk,
          COUNT(DISTINCT a.id) assets
        {flt.BASE_FROM}{where}
        GROUP BY grp ORDER BY critical DESC, high DESC, open DESC LIMIT ?""",
        [start, end, *params, limit], conn)

    for r in rows:
        for key in ("avg_age", "max_age", "mttr", "risk"):
            if r.get(key) is None:
                r[key] = 0
        done = (r["mitigated"] or 0) + (r["closed"] or 0)
        denom = (r["open"] or 0) + done
        r["closure_rate"] = round(100.0 * done / denom, 1) if denom else 0.0
        r["sla_breach_rate"] = round(100.0 * (r["breached"] or 0) / (r["open"] or 1), 1)
        r["dimension"] = dimension
    return rows


def group_by_type_matrix(f=None, dimension: str = "department", conn=None) -> dict:
    """Cross-tab: grouping dimension x vulnerability category (OS/DB/App/...)."""
    col = flt.GROUP_DIMENSIONS.get(dimension, "a.department")
    where, params = flt.build_where(f)
    cond = _status_condition("open", where)
    rows = _rows(f"""
        SELECT COALESCE(NULLIF({col},''),'(unassigned)') grp, v.category, COUNT(*) n
        {flt.BASE_FROM}{where}{cond} GROUP BY grp, v.category""", params, conn)
    cats = sorted({r["category"] for r in rows})
    grid: dict[str, dict[str, int]] = {}
    for r in rows:
        grid.setdefault(r["grp"], {})[r["category"]] = r["n"]
    matrix = [
        {"group": g, **{c: vals.get(c, 0) for c in cats}, "total": sum(vals.values())}
        for g, vals in grid.items()
    ]
    matrix.sort(key=lambda x: x["total"], reverse=True)
    return {"dimension": dimension, "categories": cats, "rows": matrix}


def aging_buckets(f=None, group_by: str | None = None, conn=None) -> list[dict]:
    where, params = flt.build_where(f)
    cond = _status_condition("open", where)
    if group_by:
        col = flt.GROUP_DIMENSIONS.get(group_by, "a.department")
        rows = _rows(f"""
            SELECT COALESCE(NULLIF({col},''),'(unassigned)') grp, f.age_days, f.severity_rank
            {flt.BASE_FROM}{where}{cond}""", params, conn)
        out: dict[str, dict] = {}
        for r in rows:
            entry = out.setdefault(r["grp"], {"group": r["grp"], **{b[2]: 0 for b in AGE_BUCKETS}})
            for lo, hi, label in AGE_BUCKETS:
                if lo <= (r["age_days"] or 0) <= hi:
                    entry[label] += 1
                    break
        return sorted(out.values(), key=lambda x: sum(v for k, v in x.items() if k != "group"),
                      reverse=True)

    rows = _rows(f"""
        SELECT f.age_days, f.severity {flt.BASE_FROM}{where}{cond}""", params, conn)
    buckets = [{"bucket": b[2], "n": 0, **{s: 0 for s in SEV_ORDER}} for b in AGE_BUCKETS]
    for r in rows:
        for i, (lo, hi, _label) in enumerate(AGE_BUCKETS):
            if lo <= (r["age_days"] or 0) <= hi:
                buckets[i]["n"] += 1
                buckets[i][r["severity"]] = buckets[i].get(r["severity"], 0) + 1
                break
    return buckets


def sla_performance(f=None, conn=None) -> list[dict]:
    """Per-severity SLA target vs actual, using the operator-configured policy."""
    where, params = flt.build_where(f)
    start, end = flt.period_bounds(f)
    policy = {r["severity"]: r["days"] for r in
              _conn(conn).execute("SELECT severity, days FROM sla_policy")}
    rows = _rows(f"""
        SELECT f.severity,
          SUM(CASE WHEN f.status IN ('open','reopened') THEN 1 ELSE 0 END) open,
          SUM(CASE WHEN f.status IN ('open','reopened') AND f.sla_breached=1 THEN 1 ELSE 0 END) open_breached,
          SUM(CASE WHEN f.status IN ('closed','mitigated') AND
              DATE(COALESCE(f.closed_date,f.mitigated_date)) BETWEEN DATE(?) AND DATE(?)
              THEN 1 ELSE 0 END) remediated,
          SUM(CASE WHEN f.status IN ('closed','mitigated') AND f.sla_breached=1 AND
              DATE(COALESCE(f.closed_date,f.mitigated_date)) BETWEEN DATE(?) AND DATE(?)
              THEN 1 ELSE 0 END) remediated_late,
          ROUND(AVG(CASE WHEN f.status IN ('closed','mitigated') THEN f.days_to_close END),1) mttr
        {flt.BASE_FROM}{where} GROUP BY f.severity""",
        [start, end, start, end, *params], conn)
    index = {r["severity"]: r for r in rows}
    out = []
    for sev in SEV_ORDER:
        r = index.get(sev, {})
        open_n, breached = r.get("open") or 0, r.get("open_breached") or 0
        remediated, late = r.get("remediated") or 0, r.get("remediated_late") or 0
        pop = open_n + remediated
        out.append({
            "severity": sev, "target_days": policy.get(sev),
            "open": open_n, "open_breached": breached,
            "remediated": remediated, "remediated_late": late,
            "mttr": r.get("mttr") or 0,
            "within_sla_pct": round(100.0 * (pop - breached - late) / pop, 1) if pop else 100.0,
        })
    return out


# --------------------------------------------------------------------------
# Trend (derived from finding dates - no snapshot table needed)
# --------------------------------------------------------------------------
def trend(f=None, buckets: int = 12, interval_days: int = 7, conn=None) -> list[dict]:
    where, params = flt.build_where(f)
    start, end = flt.period_bounds(f, default_days=buckets * interval_days)
    end_d = dt.date.fromisoformat(end)
    start_d = dt.date.fromisoformat(start)
    span = max((end_d - start_d).days, interval_days)
    step = max(1, span // buckets)

    points = [end_d - dt.timedelta(days=step * i) for i in range(buckets)][::-1]
    out = []
    prev: dt.date | None = None
    for pt in points:
        iso = pt.isoformat()
        row = _one(f"""
            SELECT COUNT(*) open,
              SUM(CASE WHEN f.severity_rank=4 THEN 1 ELSE 0 END) critical,
              SUM(CASE WHEN f.severity_rank=3 THEN 1 ELSE 0 END) high,
              ROUND(AVG(f.risk_score),1) avg_risk,
              ROUND(SUM(f.risk_score),0) total_risk
            {flt.BASE_FROM}{where}{' AND' if where else ' WHERE'}
              DATE(f.first_detected) <= DATE(?)
              AND (f.status IN ('open','reopened')
                   OR DATE(COALESCE(f.closed_date, f.mitigated_date, '2999-12-31')) > DATE(?))
            """, [*params, iso, iso], conn)
        window_start = (prev or (pt - dt.timedelta(days=step))).isoformat()
        flow = _one(f"""
            SELECT SUM(CASE WHEN DATE(f.first_detected) > DATE(?) AND DATE(f.first_detected) <= DATE(?)
                        THEN 1 ELSE 0 END) new,
                   SUM(CASE WHEN DATE(COALESCE(f.closed_date,f.mitigated_date)) > DATE(?)
                        AND DATE(COALESCE(f.closed_date,f.mitigated_date)) <= DATE(?) THEN 1 ELSE 0 END) remediated
            {flt.BASE_FROM}{where}""",
            [window_start, iso, window_start, iso, *params], conn)
        out.append({
            "date": iso,
            "open": row.get("open") or 0,
            "critical": row.get("critical") or 0,
            "high": row.get("high") or 0,
            "avg_risk": row.get("avg_risk") or 0,
            "total_risk": row.get("total_risk") or 0,
            "new": flow.get("new") or 0,
            "remediated": flow.get("remediated") or 0,
        })
        prev = pt
    return out


# --------------------------------------------------------------------------
# Lists
# --------------------------------------------------------------------------
FINDING_COLUMNS = """
    f.id, f.finding_key, f.status, f.severity, f.severity_rank, f.cvss_score, f.port,
    f.protocol, f.service, f.first_detected, f.last_detected, f.mitigated_date, f.closed_date,
    f.age_days, f.days_to_close, f.due_date, f.sla_days, f.sla_breached, f.reopened_count,
    f.risk_score, f.remediation_owner, f.ticket_ref, f.notes, f.exception_until,
    a.id AS asset_id, a.hostname, a.ip_address, a.os_name, a.os_family, a.department,
    a.application, a.system_owner, a.owner_email, a.environment, a.criticality, a.location,
    a.business_unit,
    v.id AS vuln_id, v.plugin_id, v.title, v.category, v.subcategory, v.product, v.cve,
    v.family, v.solution, v.exploit_available, v.classify_confidence, v.classified_by
"""


def findings_page(f=None, sort: str = "severity", direction: str = "desc",
                  page: int = 1, page_size: int = 100, conn=None) -> dict:
    where, params = flt.build_where(f)
    col = flt.SORTABLE.get(sort, "f.severity_rank")
    direction = "ASC" if str(direction).lower() == "asc" else "DESC"
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 5000))
    total = _one(f"SELECT COUNT(*) n {flt.BASE_FROM}{where}", params, conn).get("n", 0)
    rows = _rows(
        f"SELECT {FINDING_COLUMNS} {flt.BASE_FROM}{where} "
        f"ORDER BY {col} {direction}, f.age_days DESC LIMIT ? OFFSET ?",
        [*params, page_size, (page - 1) * page_size], conn)
    return {"total": total, "page": page, "page_size": page_size,
            "pages": max(1, -(-total // page_size)), "rows": rows}


def findings_all(f=None, sort: str = "severity", direction: str = "desc",
                 limit: int = 50000, conn=None) -> list[dict]:
    """Unpaged fetch for exports (respects the same filters)."""
    where, params = flt.build_where(f)
    col = flt.SORTABLE.get(sort, "f.severity_rank")
    direction = "ASC" if str(direction).lower() == "asc" else "DESC"
    return _rows(f"SELECT {FINDING_COLUMNS} {flt.BASE_FROM}{where} "
                 f"ORDER BY {col} {direction} LIMIT ?", [*params, limit], conn)


def filter_options(conn=None) -> dict:
    c = _conn(conn)

    def distinct(sql: str) -> list[str]:
        return [r[0] for r in c.execute(sql).fetchall() if r[0]]

    return {
        "status": ["open", "reopened", "mitigated", "closed", "risk_accepted", "false_positive"],
        "severity": SEV_ORDER,
        "department": distinct("SELECT DISTINCT department FROM assets ORDER BY 1"),
        "application": distinct("SELECT DISTINCT application FROM assets ORDER BY 1"),
        "system_owner": distinct("SELECT DISTINCT system_owner FROM assets ORDER BY 1"),
        "environment": distinct("SELECT DISTINCT environment FROM assets ORDER BY 1"),
        "criticality": distinct("SELECT DISTINCT criticality FROM assets ORDER BY 1"),
        "os_family": distinct("SELECT DISTINCT os_family FROM assets ORDER BY 1"),
        "location": distinct("SELECT DISTINCT location FROM assets ORDER BY 1"),
        "business_unit": distinct("SELECT DISTINCT business_unit FROM assets ORDER BY 1"),
        "category": distinct("SELECT DISTINCT category FROM vulns ORDER BY 1"),
        "subcategory": distinct("SELECT DISTINCT subcategory FROM vulns ORDER BY 1"),
        "remediation_owner": distinct("SELECT DISTINCT remediation_owner FROM findings ORDER BY 1"),
        "dimensions": list(flt.GROUP_DIMENSIONS.keys()),
        "sortable": list(flt.SORTABLE.keys()),
    }


def top_vulnerabilities(f=None, limit: int = 15, conn=None) -> list[dict]:
    where, params = flt.build_where(f)
    cond = _status_condition("open", where)
    return _rows(f"""
        SELECT v.id vuln_id, v.title, v.severity, v.category, v.subcategory, v.cve,
               v.exploit_available, COUNT(*) instances, COUNT(DISTINCT a.id) assets,
               ROUND(AVG(f.age_days)) avg_age, MAX(f.age_days) max_age
        {flt.BASE_FROM}{where}{cond}
        GROUP BY v.id ORDER BY (v.severity_rank * 1000 + COUNT(*)) DESC LIMIT ?""",
        [*params, limit], conn)


def executive(f=None, conn=None) -> dict:
    return {
        "kpis": kpis(f, conn),
        "severity": severity_breakdown(f, "open", conn),
        "trend": trend(f, conn=conn),
        "sla": sla_performance(f, conn),
        "aging": aging_buckets(f, conn=conn),
        "by_category": group_summary("category", f, conn=conn),
        "by_department": group_summary("department", f, limit=10, conn=conn),
        "by_application": group_summary("application", f, limit=10, conn=conn),
        "by_owner": group_summary("system_owner", f, limit=10, conn=conn),
        "by_environment": group_summary("environment", f, conn=conn),
        "top_vulnerabilities": top_vulnerabilities(f, conn=conn),
    }
