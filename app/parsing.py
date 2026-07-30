"""Scan-report parsing: CSV / TSV / XLSX / JSON / .nessus, with column auto-mapping.

The importer is scanner-agnostic: it maps whatever headers a file has onto a
canonical field set using an alias table, so Nessus, Qualys, Rapid7, OpenVAS,
Defender and hand-built spreadsheets all land in the same shape.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
RANK_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

# canonical field -> accepted header spellings (normalised: lowercase, alnum only)
ALIASES: dict[str, list[str]] = {
    "hostname": ["host", "hostname", "dnsname", "fqdn", "assetname", "machinename",
                 "devicename", "computername", "netbiosname", "target", "asset", "systemname",
                 "server", "servername"],
    "ip_address": ["ip", "ipaddress", "ipv4address", "hostip", "assetip", "ipaddresses",
                   "primaryip", "address"],
    "os_name": ["os", "osname", "operatingsystem", "hostos", "platform", "ostype"],
    "plugin_id": ["pluginid", "plugin", "qid", "vulnerabilityid", "vulnid", "checkid",
                  "id", "signatureid", "nvt oid", "oid", "cveid2"],
    "title": ["name", "pluginname", "title", "vulnerability", "vulnerabilitytitle",
              "vulnname", "threat", "issue", "vulnerabilityname", "finding", "summary",
              "description1", "qidtitle"],
    "severity": ["severity", "risk", "riskfactor", "risklevel", "severitylevel",
                 "criticality", "vulnerabilityseverity", "threatlevel"],
    "cvss_score": ["cvss", "cvssscore", "cvssbasescore", "cvss3basescore", "cvssv3basescore",
                   "cvssv2basescore", "cvss3", "basescore", "score", "cvssbase"],
    "cvss_vector": ["cvssvector", "cvss3vector", "cvssv3vector", "vector"],
    "cve": ["cve", "cves", "cveid", "cvelist", "cveids"],
    "port": ["port", "portnumber", "affectedport"],
    "protocol": ["protocol", "proto", "transport"],
    "service": ["service", "servicename", "svc", "protocolservice"],
    "solution": ["solution", "remediation", "fix", "recommendation", "patch", "solutiontype"],
    "description": ["description", "synopsis", "details", "diagnosis", "impact", "threatdetail"],
    "family": ["family", "pluginfamily", "vulncategory", "category", "vulnerabilitytype",
               "type", "pluginfamilyname", "group"],
    "product": ["product", "affectedproduct", "software", "application1", "package",
                "vendorproduct"],
    "exploit_available": ["exploitavailable", "exploitable", "exploit", "metasploit",
                          "exploitability", "publicexploit", "exploitmaturity"],
    "first_detected": ["firstfound", "firstdiscovered", "firstdetected", "firstseen",
                       "firstobserved", "discovereddate", "detectiondate1"],
    "last_detected": ["lastfound", "lastdetected", "lastseen", "lastobserved", "scandate",
                      "detected", "detectiondate", "date"],
    # enrichment / ownership columns (pass-through if the file carries them)
    "department": ["department", "dept", "businessunit1", "owningdepartment", "division"],
    "application": ["application", "app", "applicationname", "systemname1", "appname",
                    "businessapplication", "service1"],
    "system_owner": ["systemowner", "owner", "assetowner", "applicationowner", "custodian",
                     "responsible", "systemcustodian"],
    "owner_email": ["owneremail", "email", "contactemail", "ownercontact"],
    "business_unit": ["businessunit", "bu", "unit", "lineofbusiness"],
    "environment": ["environment", "env", "envtype", "stage", "tier"],
    "criticality": ["assetcriticality", "businesscriticality", "importance", "assettier"],
    "location": ["location", "site", "datacenter", "region", "branch"],
    "tags": ["tags", "labels", "assettags"],
    # mitigation-file columns
    "status": ["status", "state", "mitigationstatus", "remediationstatus", "vulnstatus",
               "currentstatus", "disposition"],
    "mitigated_date": ["mitigateddate", "fixeddate", "remediateddate", "dateremediated",
                       "closeddate", "dateclosed", "resolutiondate", "datefixed"],
    "ticket_ref": ["ticket", "ticketref", "ticketnumber", "changeref", "incident", "rfc",
                   "jira", "changerequest"],
    "notes": ["notes", "comment", "comments", "remarks", "justification"],
    "remediation_owner": ["remediationowner", "assignee", "assignedto", "fixowner"],
}

_ALIAS_INDEX: dict[str, str] = {}
for _field, _names in ALIASES.items():
    for _n in _names:
        _ALIAS_INDEX.setdefault(_n, _field)


def norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (h or "").strip().lower())


def build_mapping(headers: list[str]) -> dict[str, str]:
    """header -> canonical field. First header wins for a given field."""
    mapping: dict[str, str] = {}
    used: set[str] = set()
    for h in headers:
        field = _ALIAS_INDEX.get(norm_header(h))
        if field and field not in used:
            mapping[h] = field
            used.add(field)
    return mapping


# --------------------------------------------------------------------------
# value coercion
# --------------------------------------------------------------------------
def to_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        m = re.search(r"\d+(\.\d+)?", str(v))
        return float(m.group()) if m else None


TRUE_WORDS = {"true", "yes", "y", "1", "available", "exploitable", "public", "high",
              "functional", "active", "poc", "weaponized"}


def to_bool(v: Any) -> int:
    if v is None:
        return 0
    s = str(v).strip().lower()
    if s in {"", "false", "no", "n", "0", "none", "not available", "unproven", "na", "n/a"}:
        return 0
    return 1 if s in TRUE_WORDS or s.startswith("exploit") else 0


DATE_FORMATS = [
    "%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%d-%b-%Y", "%d %b %Y",
    "%b %d, %Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M",
    "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M", "%a %b %d %H:%M:%S %Y",
]


def to_date(v: Any) -> str | None:
    """Return ISO date (YYYY-MM-DD) or None."""
    if v is None or v == "":
        return None
    if isinstance(v, (dt.datetime, dt.date)):
        return (v.date() if isinstance(v, dt.datetime) else v).isoformat()
    s = str(v).strip()
    if not s:
        return None
    s = s.replace("Z", "").split("+")[0].strip()
    for fmt in DATE_FORMATS:
        try:
            return dt.datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(s).date().isoformat()
    except ValueError:
        return None


def norm_severity(value: Any, cvss: float | None = None, qualys_scale: bool = False) -> str:
    """Normalise any scanner's severity spelling/number onto 5 canonical levels."""
    if value is None or str(value).strip() == "":
        return sev_from_cvss(cvss) if cvss is not None else "Info"
    s = str(value).strip().lower()
    if s.startswith("crit") or s in {"urgent", "sev5", "p1"}:
        return "Critical"
    if s.startswith("high") or s in {"severe", "important", "sev4", "p2"}:
        return "High"
    if s.startswith("med") or s.startswith("mod") or s in {"warning", "sev3", "p3"}:
        return "Medium"
    if s.startswith("low") or s in {"minor", "sev2", "p4"}:
        return "Low"
    if s.startswith("info") or s in {"none", "log", "sev1", "p5", "notice"}:
        return "Info"
    num = to_float(s)
    if num is None:
        return sev_from_cvss(cvss) if cvss is not None else "Info"
    n = int(num)
    if qualys_scale:  # Qualys/OpenVAS QID severity 1..5
        return {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}.get(n, "Info")
    if 0 <= n <= 4:  # Nessus/Tenable 0..4
        return RANK_SEVERITY.get(n, "Info")
    return sev_from_cvss(float(num))


def sev_from_cvss(score: float | None) -> str:
    if score is None:
        return "Info"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


# --------------------------------------------------------------------------
# readers
# --------------------------------------------------------------------------
def _sniff_text(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def read_csv(raw: bytes) -> tuple[list[str], list[dict]]:
    text = _sniff_text(raw)
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [h for h in (reader.fieldnames or []) if h is not None]
    rows = [{k: v for k, v in r.items() if k is not None} for r in reader]
    return headers, rows


def read_xlsx(raw: bytes, sheet: str | None = None) -> tuple[list[str], list[dict]]:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    ws = wb[sheet] if sheet and sheet in wb.sheetnames else wb[wb.sheetnames[0]]
    it = ws.iter_rows(values_only=True)
    headers: list[str] = []
    for row in it:
        if row and any(c is not None and str(c).strip() for c in row):
            headers = [str(c).strip() if c is not None else f"col{i}" for i, c in enumerate(row)]
            break
    rows = []
    for row in it:
        if row is None or all(c is None or str(c).strip() == "" for c in row):
            continue
        rows.append({headers[i]: row[i] for i in range(min(len(headers), len(row)))})
    wb.close()
    return headers, rows


def read_json(raw: bytes) -> tuple[list[str], list[dict]]:
    data = json.loads(_sniff_text(raw))
    if isinstance(data, dict):
        for key in ("results", "findings", "vulnerabilities", "data", "items", "rows"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    rows = [r for r in data if isinstance(r, dict)]
    headers: list[str] = []
    for r in rows[:200]:
        for k in r:
            if k not in headers:
                headers.append(k)
    return headers, [{k: _flatten(v) for k, v in r.items()} for r in rows]


def _flatten(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v)[:2000]
    return v


NESSUS_SEV = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}


def read_nessus(raw: bytes) -> tuple[list[str], list[dict]]:
    """Parse a native Tenable .nessus XML export."""
    root = ET.fromstring(raw)
    rows: list[dict] = []
    for host in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "") for t in host.iter("tag")}
        hostname = props.get("host-fqdn") or props.get("netbios-name") or host.get("name")
        for item in host.iter("ReportItem"):
            def txt(tag: str) -> str:
                el = item.find(tag)
                return (el.text or "").strip() if el is not None and el.text else ""

            cves = [e.text for e in item.findall("cve") if e.text]
            rows.append({
                "Host": hostname,
                "IP Address": props.get("host-ip") or host.get("name"),
                "OS": props.get("operating-system", ""),
                "Plugin ID": item.get("pluginID"),
                "Name": item.get("pluginName"),
                "Family": item.get("pluginFamily"),
                "Severity": NESSUS_SEV.get(item.get("severity", "0"), "Info"),
                "CVSS Base Score": txt("cvss3_base_score") or txt("cvss_base_score"),
                "CVSS Vector": txt("cvss3_vector") or txt("cvss_vector"),
                "CVE": ", ".join(cves),
                "Port": item.get("port"),
                "Protocol": item.get("protocol"),
                "Service": item.get("svc_name"),
                "Solution": txt("solution"),
                "Description": txt("synopsis") or txt("description"),
                "Exploit Available": txt("exploit_available"),
                "Plugin Output": txt("plugin_output")[:4000],
            })
    headers = list(rows[0].keys()) if rows else []
    return headers, rows


def read_any(raw: bytes, filename: str, sheet: str | None = None) -> tuple[list[str], list[dict]]:
    name = (filename or "").lower()
    if name.endswith((".xlsx", ".xlsm", ".xltx")):
        return read_xlsx(raw, sheet)
    if name.endswith(".json"):
        return read_json(raw)
    if name.endswith((".nessus", ".xml")):
        try:
            return read_nessus(raw)
        except ET.ParseError:
            pass
    return read_csv(raw)


def looks_like_qualys(headers: list[str]) -> bool:
    hs = {norm_header(h) for h in headers}
    return "qid" in hs or "qidtitle" in hs
