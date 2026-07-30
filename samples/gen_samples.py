"""Generate realistic demo scan files so the app can be exercised end-to-end.

Creates in this directory:
  scan_week1.csv     - Nessus-style export, week 1
  scan_week2.csv     - week 2 (some fixed, some new, one reopened)
  mitigations.xlsx   - remediation evidence returned by system owners
  asset_inventory.csv- ownership enrichment (department / application / owner)
"""
from __future__ import annotations

import csv
import datetime as dt
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
random.seed(7)

DEPTS = ["Retail Banking", "Corporate Banking", "Treasury", "IT Operations", "Digital Channels",
         "Risk & Compliance", "HR", "Finance"]
APPS = ["Core Banking", "Internet Banking", "Mobile Banking", "SWIFT Gateway", "Card Management",
        "HR Portal", "Data Warehouse", "Email", "ATM Switch", "Intranet"]
OWNERS = ["A. Mensah", "K. Boateng", "N. Okafor", "S. Adeyemi", "T. Owusu", "J. Bello", "F. Danso"]
ENVS = ["Production", "Production", "Production", "UAT", "Development"]
CRIT = ["Critical", "High", "High", "Medium", "Low"]

VULNS = [
    ("57582", "Microsoft Windows KB5034441: Security Update for Windows Server 2019", "Critical", 9.8, "Windows : Microsoft Bulletins", "CVE-2024-21310", 445, "tcp", "cifs"),
    ("11219", "Oracle Database Server Multiple Vulnerabilities (Jan 2024 CPU)", "High", 8.1, "Databases", "CVE-2024-20932", 1521, "tcp", "oracle-tns"),
    ("64784", "Microsoft SQL Server Unsupported Version Detection", "Critical", 10.0, "Databases", "", 1433, "tcp", "mssql"),
    ("48243", "Apache HTTP Server 2.4.x < 2.4.58 Multiple Vulnerabilities", "High", 7.5, "Web Servers", "CVE-2023-45802", 443, "tcp", "www"),
    ("112731", "Apache Log4j 1.2 Deserialization Remote Code Execution", "Critical", 9.8, "Web Servers", "CVE-2021-4104", 8443, "tcp", "www"),
    ("42873", "SSL Medium Strength Cipher Suites Supported (SWEET32)", "Medium", 5.3, "General", "CVE-2016-2183", 443, "tcp", "www"),
    ("51192", "SSL Certificate Cannot Be Trusted (self-signed)", "Medium", 6.5, "General", "", 443, "tcp", "www"),
    ("26928", "SMB Signing not required", "Medium", 5.3, "Misc.", "", 445, "tcp", "cifs"),
    ("10883", "Cross-Site Scripting (XSS) in login form parameter", "High", 7.2, "CGI abuses : XSS", "CVE-2023-99991", 443, "tcp", "www"),
    ("70658", "SSH Server CBC Mode Ciphers Enabled", "Low", 3.7, "Misc.", "", 22, "tcp", "ssh"),
    ("152742", "MySQL 5.7.x < 5.7.44 Multiple Vulnerabilities", "High", 7.8, "Databases", "CVE-2023-22084", 3306, "tcp", "mysql"),
    ("134862", "Google Chrome < 121.0.6167.85 Multiple Vulnerabilities", "High", 8.8, "Windows", "CVE-2024-0807", 0, "", ""),
    ("58987", "PHP Unsupported Version Detection", "Critical", 9.1, "CGI abuses", "", 80, "tcp", "www"),
    ("20007", "SSL Version 2 and 3 Protocol Detection (POODLE)", "Medium", 6.8, "Service detection", "CVE-2014-3566", 443, "tcp", "www"),
    ("35291", "VMware ESXi 7.0 < ESXi70U3 Multiple Vulnerabilities", "High", 8.2, "Misc.", "CVE-2023-20900", 902, "tcp", ""),
    ("104743", "Cisco IOS XE Web UI Privilege Escalation", "Critical", 10.0, "CISCO", "CVE-2023-20198", 443, "tcp", "www"),
    ("90317", "Default Credentials Detected on Management Interface", "Critical", 9.4, "Misc.", "", 8080, "tcp", "www"),
    ("15901", "Adobe Acrobat Reader < 23.008.20470 Multiple Vulnerabilities", "Medium", 6.1, "Windows", "CVE-2023-44366", 0, "", ""),
    ("77032", "Red Hat Enterprise Linux glibc Buffer Overflow (RHSA-2024:0001)", "High", 7.8, "Red Hat Local Security Checks", "CVE-2023-6246", 0, "", ""),
    ("101002", "Nginx 1.20 < 1.24.0 HTTP/2 Rapid Reset", "High", 7.5, "Web Servers", "CVE-2023-44487", 443, "tcp", "www"),
]

HEADER = ["Host", "IP Address", "OS", "Plugin ID", "Name", "Family", "Severity",
          "CVSS Base Score", "CVE", "Port", "Protocol", "Service", "Solution",
          "Exploit Available", "First Found", "Last Found", "Department", "Application",
          "System Owner", "Owner Email", "Environment", "Asset Criticality", "Location"]

OS_POOL = ["Microsoft Windows Server 2019 Standard", "Microsoft Windows Server 2016",
           "Red Hat Enterprise Linux 8.6", "Ubuntu 20.04 LTS", "Oracle Linux 8",
           "VMware ESXi 7.0", "Cisco IOS XE 17.6"]


def make_hosts(n=45):
    hosts = []
    for i in range(1, n + 1):
        dept = random.choice(DEPTS)
        hosts.append({
            "Host": f"gh-{'srv' if i % 5 else 'db'}-{i:03d}.bank.local",
            "IP Address": f"10.{10 + i % 6}.{i % 24}.{20 + i}",
            "OS": random.choice(OS_POOL),
            "Department": dept,
            "Application": random.choice(APPS),
            "System Owner": random.choice(OWNERS),
            "Owner Email": "",
            "Environment": random.choice(ENVS),
            "Asset Criticality": random.choice(CRIT),
            "Location": random.choice(["Accra HQ", "Kumasi DR", "Tema Branch", "Cloud - Azure"]),
        })
    for h in hosts:
        h["Owner Email"] = h["System Owner"].split()[-1].lower() + "@bank.com.gh"
    return hosts


def rows_for(hosts, week_date: dt.date, first_date: dt.date, drop=0.0, add=0.0, seed=1):
    rnd = random.Random(seed)
    out = []
    for h in hosts:
        n = rnd.randint(2, 7)
        picks = rnd.sample(VULNS, n)
        for v in picks:
            if rnd.random() < drop:
                continue
            pid, name, sev, cvss, fam, cve, port, proto, svc = v
            out.append({
                **h,
                "Plugin ID": pid, "Name": name, "Family": fam, "Severity": sev,
                "CVSS Base Score": cvss, "CVE": cve, "Port": port, "Protocol": proto,
                "Service": svc,
                "Solution": "Apply the vendor-supplied patch or upgrade to a fixed version.",
                "Exploit Available": "true" if cvss >= 9.0 and rnd.random() > 0.4 else "false",
                "First Found": first_date.isoformat(),
                "Last Found": week_date.isoformat(),
            })
        if add and rnd.random() < add:
            pid, name, sev, cvss, fam, cve, port, proto, svc = rnd.choice(VULNS)
            out.append({
                **h, "Plugin ID": pid, "Name": name, "Family": fam, "Severity": sev,
                "CVSS Base Score": cvss, "CVE": cve, "Port": port, "Protocol": proto,
                "Service": svc, "Solution": "Apply the vendor-supplied patch.",
                "Exploit Available": "false", "First Found": week_date.isoformat(),
                "Last Found": week_date.isoformat(),
            })
    return out


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    today = dt.date.today()
    w1, w2 = today - dt.timedelta(days=35), today - dt.timedelta(days=7)
    hosts = make_hosts()
    r1 = rows_for(hosts, w1, w1 - dt.timedelta(days=20), seed=11)
    write_csv(HERE / "scan_week1.csv", r1)
    r2 = rows_for(hosts, w2, w1 - dt.timedelta(days=20), drop=0.30, add=0.25, seed=11)
    write_csv(HERE / "scan_week2.csv", r2)

    with (HERE / "asset_inventory.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["Host", "Department", "Application", "System Owner",
                                           "Owner Email", "Environment", "Asset Criticality"],
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(hosts)

    # mitigation evidence workbook
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Mitigations"
    ws.append(["Hostname", "Plugin ID", "Vulnerability", "Status", "Mitigated Date",
               "Ticket", "Assigned To", "Comments"])
    rnd = random.Random(3)
    for row in rnd.sample(r2, min(60, len(r2))):
        ws.append([row["Host"], row["Plugin ID"], row["Name"], "Mitigated",
                   (w2 + dt.timedelta(days=rnd.randint(1, 5))).isoformat(),
                   f"CHG{rnd.randint(10000, 99999)}", row["System Owner"],
                   "Patch deployed via WSUS and verified by system owner"])
    wb.save(HERE / "mitigations.xlsx")
    print(f"week1 rows={len(r1)}  week2 rows={len(r2)}  hosts={len(hosts)}")


if __name__ == "__main__":
    main()
