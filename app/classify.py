"""Vulnerability type classification engine.

Four-stage cascade, highest-confidence first:
  1. regex rules over a text haystack (title + family + product + solution + description)
  2. scanner plugin-family mapping
  3. port / service heuristics
  4. fallback -> Other (low confidence, surfaced in the console for triage)

Rules live in the `class_rules` table so an operator can add, disable or
re-prioritise them at runtime without a code change. Built-in rules are seeded
once and flagged builtin=1.
"""
from __future__ import annotations

import re
import sqlite3
import datetime as dt

from . import db

CATEGORIES = [
    "OS", "Database", "Application", "Web/Middleware", "Network", "Virtualization",
    "Security", "Cloud/Container", "Crypto/PKI", "Configuration", "Other",
]

# (name, priority, pattern, category, subcategory, product, confidence)
BUILTIN_RULES: list[tuple[str, int, str, str, str, str, float]] = [
    # ---- Databases (must precede vendor-OS rules: "Microsoft SQL Server") ----
    ("Oracle Database", 10, r"\boracle\s+(database|rdbms|db\b)|tns\s+listener|oracle\s+critical\s+patch", "Database", "Oracle Database", "Oracle Database", 0.96),
    ("Microsoft SQL Server", 10, r"\b(microsoft\s+)?sql\s+server\b|\bmssql\b", "Database", "Microsoft SQL Server", "SQL Server", 0.96),
    ("MySQL / MariaDB", 10, r"\bmysql\b|\bmariadb\b", "Database", "MySQL/MariaDB", "MySQL", 0.96),
    ("PostgreSQL", 10, r"\bpostgre\s?sql\b|\bpostgres\b", "Database", "PostgreSQL", "PostgreSQL", 0.96),
    ("MongoDB", 10, r"\bmongodb\b", "Database", "MongoDB", "MongoDB", 0.95),
    ("Redis", 10, r"\bredis\b", "Database", "Redis", "Redis", 0.95),
    ("IBM Db2", 10, r"\bdb2\b", "Database", "IBM Db2", "Db2", 0.94),
    ("Sybase / SAP ASE", 10, r"\bsybase\b|\bsap\s+ase\b", "Database", "Sybase ASE", "Sybase", 0.94),
    ("Elasticsearch", 12, r"\belasticsearch\b|\bopensearch\b", "Database", "Elasticsearch", "Elasticsearch", 0.93),
    ("Other datastores", 12, r"\bcassandra\b|\bcouchdb\b|\bmemcached\b|\bneo4j\b|\binformix\b|\bteradata\b|\bsqlite\b|\bfirebird\b", "Database", "NoSQL/Other", "", 0.9),
    ("Generic database", 30, r"\bdatabase\s+(server|instance|engine)\b|\brdbms\b|\bdbms\b|\bdata\s?base\b", "Database", "General", "", 0.7),

    # ---- Virtualization ----
    ("VMware", 14, r"\bvmware\b|\besxi?\b|\bvcenter\b|\bvsphere\b|\bvrealize\b", "Virtualization", "VMware", "VMware", 0.95),
    ("Hyper-V / Xen / KVM", 14, r"\bhyper-?v\b|\bcitrix\s+(xen|hypervisor)\b|\bxenserver\b|\bproxmox\b|\bqemu\b|\bkvm\b|\bvirtualbox\b", "Virtualization", "Hypervisor", "", 0.93),

    # ---- Network / infrastructure devices ----
    ("Cisco", 16, r"\bcisco\b|\bios-?xe\b|\bnx-?os\b|\basa\s+software\b", "Network", "Cisco", "Cisco", 0.94),
    ("Fortinet / Palo Alto / Juniper", 16, r"\bfortios\b|\bfortigate\b|\bfortinet\b|\bpan-?os\b|\bpalo\s+alto\b|\bjunos\b|\bjuniper\b", "Network", "Firewall/Router", "", 0.94),
    ("F5 / Citrix ADC", 16, r"\bbig-?ip\b|\bf5\s+networks\b|\bnetscaler\b|\bcitrix\s+adc\b", "Network", "Load Balancer", "", 0.93),
    ("Network protocol weakness", 22, r"\bsnmp\b.*(default|public|community)|\btelnet\b|\bmikrotik\b|\bhuawei\s+vrp\b|\bswitch\s+firmware\b", "Network", "Device/Protocol", "", 0.85),

    # ---- Web servers / middleware ----
    ("Apache HTTP Server", 18, r"\bapache\s+(http|httpd|web\s+server)\b|\bhttpd\b", "Web/Middleware", "Apache HTTP", "Apache HTTP Server", 0.95),
    ("Nginx", 18, r"\bnginx\b", "Web/Middleware", "Nginx", "nginx", 0.95),
    ("Microsoft IIS", 18, r"\biis\b|\binternet\s+information\s+services\b", "Web/Middleware", "IIS", "IIS", 0.95),
    ("Tomcat / Jetty", 18, r"\btomcat\b|\bjetty\b|\bglassfish\b", "Web/Middleware", "Java Servlet Container", "Tomcat", 0.95),
    ("JBoss / WebLogic / WebSphere", 18, r"\bjboss\b|\bwildfly\b|\bweblogic\b|\bwebsphere\b", "Web/Middleware", "App Server", "", 0.95),
    ("Message brokers", 20, r"\brabbitmq\b|\bactivemq\b|\bkafka\b|\bmq\s+series\b|\bibm\s+mq\b", "Web/Middleware", "Messaging", "", 0.9),

    # ---- Web application weaknesses ----
    ("Injection / XSS / traversal", 24, r"\bsql\s+injection\b|\bcross-?site\s+scripting\b|\bxss\b|\bcsrf\b|\bcross-?site\s+request\s+forgery\b|\bdirectory\s+traversal\b|\bpath\s+traversal\b|\blocal\s+file\s+inclusion\b|\bcommand\s+injection\b|\bxxe\b|\bssrf\b|\bdeserialization\b", "Application", "Web Application", "", 0.92),
    ("Web hygiene", 26, r"\bclickjacking\b|\bmissing\s+(security\s+)?header\b|\bx-frame-options\b|\bcontent\s+security\s+policy\b|\bdirectory\s+(listing|indexing)\b|\bhttp\s+trace\b|\bcookie\s+without\s+(secure|httponly)\b|\bautocomplete\b", "Application", "Web Hygiene", "", 0.88),
    ("CMS platforms", 24, r"\bwordpress\b|\bdrupal\b|\bjoomla\b|\bmagento\b|\bsharepoint\b", "Application", "CMS/Portal", "", 0.93),

    # ---- Application software ----
    ("Java runtime / frameworks", 23, r"\b(oracle\s+)?jre\b|\bjava\s+(runtime|se|jdk)\b|\blog4j\b|\bspring\s+(framework|boot)\b|\bstruts\b|\bjackson-databind\b", "Application", "Java Platform", "Java", 0.93),
    (".NET / runtimes", 28, r"\.net\s+(framework|core)\b|\basp\.net\b|\bnode\.?js\b|\bpython\b\s+\d|\bphp\b|\bruby\b|\bperl\b|\bgolang\b|\bopenjdk\b", "Application", "Runtime/Framework", "", 0.9),
    ("Browsers", 28, r"\bgoogle\s+chrome\b|\bmozilla\s+firefox\b|\bmicrosoft\s+edge\b|\bchromium\b|\bsafari\b|\binternet\s+explorer\b", "Application", "Browser", "", 0.94),
    ("Office / productivity", 28, r"\bmicrosoft\s+(office|word|excel|powerpoint|outlook|access|visio)\b|\badobe\s+(acrobat|reader|flash|air)\b|\blibreoffice\b|\bopenoffice\b", "Application", "Productivity", "", 0.94),
    ("Mail / collaboration", 28, r"\bmicrosoft\s+exchange\b|\bpostfix\b|\bsendmail\b|\bexim\b|\bzimbra\b|\blotus\s+domino\b|\bslack\b|\bzoom\b|\bteams\b", "Application", "Mail/Collaboration", "", 0.92),
    ("Enterprise apps", 28, r"\bsap\s+(netweaver|erp|hana)\b|\bpeoplesoft\b|\be-?business\s+suite\b|\bsiebel\b|\bdynamics\b|\bjira\b|\bconfluence\b|\bgitlab\b|\bjenkins\b|\bsplunk\b|\bmoveit\b|\bfilezilla\b", "Application", "Enterprise Software", "", 0.92),
    ("Client utilities", 30, r"\b7-?zip\b|\bwinrar\b|\bnotepad\+\+\b|\bputty\b|\bwinscp\b|\bvlc\b|\bteamviewer\b|\banydesk\b|\bcitrix\s+workspace\b|\bgit\s+for\s+windows\b", "Application", "Client Utility", "", 0.9),
    ("Backup / storage software", 30, r"\bveeam\b|\bcommvault\b|\bnetbackup\b|\bveritas\b|\bnas\b\s+firmware", "Application", "Backup/Storage", "", 0.9),

    # ---- Cloud / container ----
    ("Container platform", 26, r"\bdocker\b|\bkubernetes\b|\bk8s\b|\bcontainerd\b|\bopenshift\b|\bhelm\b|\bharbor\b", "Cloud/Container", "Container Platform", "", 0.92),
    ("Cloud service", 26, r"\baws\s+(s3|ec2|iam)\b|\bazure\s+(storage|ad|blob)\b|\bgcp\b|\bs3\s+bucket\b|\bcloud\s+misconfiguration\b", "Cloud/Container", "Cloud Service", "", 0.88),

    # ---- Security tooling ----
    ("Endpoint security agent", 32, r"\bmcafee\b|\bsymantec\b|\btrend\s+micro\b|\bsophos\b|\bkaspersky\b|\bcrowdstrike\b|\bsentinelone\b|\bcarbon\s+black\b|\bantivirus\b|\bendpoint\s+protection\b", "Security", "Endpoint Agent", "", 0.9),
    ("Missing/disabled control", 34, r"\bantivirus\s+(not|out\s+of\s+date|disabled)\b|\bfirewall\s+disabled\b|\bno\s+agent\b|\bhost\s+firewall\b", "Security", "Control Gap", "", 0.85),

    # ---- Operating systems (after vendor product rules) ----
    ("Windows OS patch", 40, r"\bkb\d{6,}\b|\bmicrosoft\s+windows\b|\bwindows\s+(server\s+)?(2008|2012|2016|2019|2022|2025|7|8|10|11)\b|\bsecurity\s+update\s+for\s+windows\b|\bwindows\s+(kernel|smb|rdp|lsass|netlogon|print\s+spooler)\b|\bmicrosoft\s+bulletin", "OS", "Windows", "Windows", 0.94),
    ("Linux OS patch", 40, r"\b(rhel|red\s?hat\s+enterprise|centos|rocky\s+linux|almalinux|ubuntu|debian|suse|sles|oracle\s+linux|amazon\s+linux)\b|\blinux\s+kernel\b|\bglibc\b|\bopenssh\b|\bsudo\b|\bbash\b|\bsystemd\b|\bkernel:\s", "OS", "Linux", "Linux", 0.94),
    ("Unix OS patch", 40, r"\b(aix|solaris|hp-?ux|freebsd|openbsd|netbsd)\b", "OS", "Unix", "", 0.93),
    ("macOS patch", 40, r"\bmac\s?os\b|\bos\s+x\b|\bapple\s+security\s+update\b", "OS", "macOS", "macOS", 0.93),
    ("OS end of life", 42, r"\bunsupported\s+(version|operating\s+system|os)\b|\bend\s+of\s+(life|support)\b|\bobsolete\s+(os|operating)\b|\beol\b", "OS", "End of Life", "", 0.8),
    ("Generic missing patch", 44, r"\bmissing\s+(security\s+)?(patch|update)\b|\bpatch\s+not\s+(applied|installed)\b|\bsecurity\s+rollup\b", "OS", "Patch Management", "", 0.6),

    # ---- Crypto / PKI ----
    ("OpenSSL", 46, r"\bopenssl\b|\blibssl\b|\bgnutls\b", "Crypto/PKI", "Crypto Library", "OpenSSL", 0.93),
    ("TLS / certificate weakness", 48, r"\bssl\b|\btls\b|\bcertificates?\b|\bciphers?\b|\bssh\s+(server|weak|cbc|hmac)|\bcbc\s+mode\b|\bsha-?1\b|\brc4\b|\bmd5\s+signature\b|\bdiffie-?hellman\b|\bself-?signed\b|\bexpired\s+cert|\bpoodle\b|\bbeast\b|\bsweet32\b|\blogjam\b|\bfreak\b|\bdrown\b|\bheartbleed\b", "Crypto/PKI", "TLS/Certificate", "", 0.9),

    # ---- Configuration / hardening ----
    ("Default or weak credentials", 50, r"\bdefault\s+(password|credential|account|login)s?\b|\bweak\s+passwords?\b|\bblank\s+passwords?\b|\banonymous\s+(access|ftp|login)\b|\bguest\s+account\b|\bpassword\s+policy\b", "Configuration", "Credential Hygiene", "", 0.92),
    ("Hardening gap", 52, r"\bsmb\s+signing\b|\bsmbv1\b|\bnull\s+session\b|\bregistry\s+permission\b|\bshare\s+permission\b|\bunquoted\s+service\s+path\b|\baudit\s+policy\b|\binsecure\s+configuration\b|\bmisconfigur", "Configuration", "Hardening", "", 0.88),
    ("Information disclosure", 54, r"\binformation\s+disclosure\b|\bbanner\s+(grab|disclosure)\b|\bservice\s+detection\b|\bversion\s+disclosure\b|\benumeration\b", "Configuration", "Information Disclosure", "", 0.6),
]

# scanner plugin-family -> (category, subcategory)
FAMILY_MAP: list[tuple[str, str, str]] = [
    ("microsoft bulletin", "OS", "Windows"),
    ("windows", "OS", "Windows"),
    ("red hat local", "OS", "Linux"), ("ubuntu local", "OS", "Linux"),
    ("debian local", "OS", "Linux"), ("centos local", "OS", "Linux"),
    ("suse local", "OS", "Linux"), ("oracle linux local", "OS", "Linux"),
    ("amazon linux local", "OS", "Linux"), ("fedora local", "OS", "Linux"),
    ("linux", "OS", "Linux"), ("solaris local", "OS", "Unix"),
    ("aix local", "OS", "Unix"), ("hp-ux local", "OS", "Unix"),
    ("macos x local", "OS", "macOS"), ("mac os", "OS", "macOS"),
    ("database", "Database", "General"),
    ("web servers", "Web/Middleware", "Web Server"),
    ("cgi abuses", "Application", "Web Application"),
    ("web application", "Application", "Web Application"),
    ("firewall", "Network", "Firewall"),
    ("cisco", "Network", "Cisco"), ("junos", "Network", "Juniper"),
    ("snmp", "Network", "Device/Protocol"), ("dns", "Network", "DNS"),
    ("netware", "Network", "Device/Protocol"),
    ("virtualization", "Virtualization", "Hypervisor"),
    ("vmware", "Virtualization", "VMware"),
    ("misc", "Other", "Uncategorised"),
    ("general", "Other", "Uncategorised"),
    ("service detection", "Configuration", "Information Disclosure"),
    ("settings", "Configuration", "Hardening"),
    ("policy compliance", "Configuration", "Hardening"),
    ("backdoors", "Security", "Malware"),
    ("malware", "Security", "Malware"),
    ("scada", "Network", "OT/SCADA"),
    ("mobile devices", "Application", "Mobile"),
]

PORT_MAP: dict[str, tuple[str, str]] = {
    "1433": ("Database", "Microsoft SQL Server"), "1434": ("Database", "Microsoft SQL Server"),
    "3306": ("Database", "MySQL/MariaDB"), "5432": ("Database", "PostgreSQL"),
    "1521": ("Database", "Oracle Database"), "1526": ("Database", "Oracle Database"),
    "27017": ("Database", "MongoDB"), "6379": ("Database", "Redis"),
    "9200": ("Database", "Elasticsearch"), "5984": ("Database", "NoSQL/Other"),
    "50000": ("Database", "IBM Db2"), "5000": ("Database", "Sybase ASE"),
    "80": ("Web/Middleware", "Web Server"), "443": ("Web/Middleware", "Web Server"),
    "8080": ("Web/Middleware", "Web Server"), "8443": ("Web/Middleware", "Web Server"),
    "8000": ("Web/Middleware", "Web Server"), "8888": ("Web/Middleware", "Web Server"),
    "22": ("OS", "Linux"), "23": ("Network", "Device/Protocol"),
    "445": ("OS", "Windows"), "139": ("OS", "Windows"), "3389": ("OS", "Windows"),
    "135": ("OS", "Windows"), "5985": ("OS", "Windows"),
    "25": ("Application", "Mail/Collaboration"), "110": ("Application", "Mail/Collaboration"),
    "143": ("Application", "Mail/Collaboration"), "389": ("OS", "Directory Service"),
    "636": ("OS", "Directory Service"), "53": ("Network", "DNS"),
    "21": ("Application", "File Transfer"), "161": ("Network", "Device/Protocol"),
}

SERVICE_MAP = {
    "mssql": ("Database", "Microsoft SQL Server"), "ms-sql-s": ("Database", "Microsoft SQL Server"),
    "mysql": ("Database", "MySQL/MariaDB"), "postgresql": ("Database", "PostgreSQL"),
    "oracle": ("Database", "Oracle Database"), "oracle-tns": ("Database", "Oracle Database"),
    "mongodb": ("Database", "MongoDB"), "redis": ("Database", "Redis"),
    "http": ("Web/Middleware", "Web Server"), "www": ("Web/Middleware", "Web Server"),
    "https": ("Web/Middleware", "Web Server"), "ssh": ("OS", "Linux"),
    "cifs": ("OS", "Windows"), "smb": ("OS", "Windows"), "msrdp": ("OS", "Windows"),
    "ldap": ("OS", "Directory Service"), "smtp": ("Application", "Mail/Collaboration"),
    "ftp": ("Application", "File Transfer"), "dns": ("Network", "DNS"),
    "snmp": ("Network", "Device/Protocol"), "telnet": ("Network", "Device/Protocol"),
}


def seed_builtin_rules(conn: sqlite3.Connection | None = None) -> int:
    """Insert built-in rules once; never overwrite operator edits."""
    c = conn or db.get_conn()
    now = dt.datetime.now().isoformat(timespec="seconds")
    existing = {r["name"] for r in c.execute("SELECT name FROM class_rules WHERE builtin=1")}
    added = 0
    for name, prio, pattern, cat, sub, product, conf in BUILTIN_RULES:
        if name in existing:
            continue
        c.execute(
            "INSERT INTO class_rules(name,priority,field,pattern,category,subcategory,product,"
            "confidence,enabled,builtin,created_at,updated_at) "
            "VALUES(?,?,'haystack',?,?,?,?,?,1,1,?,?)",
            (name, prio, pattern, cat, sub, product, conf, now, now),
        )
        added += 1
    c.commit()
    return added


def os_family(os_name: str | None) -> str:
    s = (os_name or "").lower()
    if not s:
        return "Unknown"
    if "windows" in s or "microsoft" in s:
        return "Windows"
    if any(k in s for k in ("linux", "ubuntu", "centos", "red hat", "rhel", "debian", "suse", "rocky", "alma")):
        return "Linux"
    if any(k in s for k in ("aix", "solaris", "hp-ux", "bsd", "unix")):
        return "Unix"
    if any(k in s for k in ("cisco", "juniper", "fortinet", "palo alto", "ios xe", "nx-os",
                            "junos", "switch", "router", "firewall", "pan-os")):
        return "Network OS"
    if re.search(r"\bmac\s?os\b|\bos\s+x\b|\bdarwin\b|\bmacintosh\b", s):
        return "macOS"
    if any(k in s for k in ("esxi", "vmware", "hypervisor")):
        return "Hypervisor"
    return "Other"


class Classifier:
    """Loads rules once per import run; cheap to instantiate."""

    def __init__(self, conn: sqlite3.Connection | None = None):
        self.conn = conn or db.get_conn()
        seed_builtin_rules(self.conn)
        self.rules = []
        for r in self.conn.execute(
            "SELECT * FROM class_rules WHERE enabled=1 ORDER BY priority ASC, id ASC"
        ):
            try:
                self.rules.append((dict(r), re.compile(r["pattern"], re.IGNORECASE)))
            except re.error:
                continue
        self._hits: dict[int, int] = {}

    # ---- main entry point -------------------------------------------------
    def classify(
        self,
        title: str = "",
        family: str = "",
        product: str = "",
        description: str = "",
        solution: str = "",
        port: str = "",
        service: str = "",
        os_name: str = "",
    ) -> dict:
        haystack = " ".join(
            [title or "", family or "", product or "", (description or "")[:400],
             (solution or "")[:300]]
        )

        for rule, rx in self.rules:
            if rx.search(haystack):
                self._hits[rule["id"]] = self._hits.get(rule["id"], 0) + 1
                return {
                    "category": rule["category"],
                    "subcategory": rule["subcategory"] or "",
                    "product": rule["product"] or product or "",
                    "confidence": float(rule["confidence"] or 0.9),
                    "classified_by": "rule",
                    "rule": rule["name"],
                }

        fam = (family or "").lower()
        for key, cat, sub in FAMILY_MAP:
            if key and key in fam:
                return {"category": cat, "subcategory": sub, "product": product or "",
                        "confidence": 0.75, "classified_by": "family", "rule": f"family:{key}"}

        svc = (service or "").strip().lower()
        if svc in SERVICE_MAP:
            cat, sub = SERVICE_MAP[svc]
            return {"category": cat, "subcategory": sub, "product": product or "",
                    "confidence": 0.55, "classified_by": "service", "rule": f"service:{svc}"}

        p = re.sub(r"[^0-9]", "", str(port or ""))
        if p in PORT_MAP:
            cat, sub = PORT_MAP[p]
            return {"category": cat, "subcategory": sub, "product": product or "",
                    "confidence": 0.45, "classified_by": "port", "rule": f"port:{p}"}

        fam_os = os_family(os_name)
        if fam_os in {"Windows", "Linux", "Unix", "macOS"}:
            return {"category": "OS", "subcategory": fam_os, "product": product or "",
                    "confidence": 0.25, "classified_by": "os-hint", "rule": f"os:{fam_os}"}

        return {"category": "Other", "subcategory": "Uncategorised", "product": product or "",
                "confidence": 0.1, "classified_by": "fallback", "rule": ""}

    def flush_hits(self) -> None:
        if not self._hits:
            return
        self.conn.executemany(
            "UPDATE class_rules SET hits = COALESCE(hits,0) + ? WHERE id = ?",
            [(n, rid) for rid, n in self._hits.items()],
        )
        self.conn.commit()
        self._hits.clear()


def reclassify_all(conn: sqlite3.Connection | None = None) -> int:
    """Re-run classification over every stored vulnerability (after rule edits)."""
    c = conn or db.get_conn()
    clf = Classifier(c)
    updated = 0
    rows = c.execute(
        "SELECT id, title, family, product, description, solution FROM vulns"
    ).fetchall()
    for r in rows:
        res = clf.classify(
            title=r["title"] or "", family=r["family"] or "", product=r["product"] or "",
            description=r["description"] or "", solution=r["solution"] or "",
        )
        c.execute(
            "UPDATE vulns SET category=?, subcategory=?, product=COALESCE(NULLIF(?,''),product), "
            "classified_by=?, classify_rule=?, classify_confidence=? WHERE id=?",
            (res["category"], res["subcategory"], res["product"], res["classified_by"],
             res["rule"], res["confidence"], r["id"]),
        )
        updated += 1
    c.commit()
    clf.flush_hits()
    return updated
