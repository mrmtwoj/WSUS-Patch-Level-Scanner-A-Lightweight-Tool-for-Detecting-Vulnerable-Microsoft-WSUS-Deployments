# Enhanced WSUS Passive Scanner (safe, non-exploit)
# Features implemented:
# - Multi-threaded scanning
# - Ports: 8530 (HTTP) and 8531 (HTTPS)
# - Safe SOAP GET (GetRollupConfiguration) to detect ServerId/ServerVersion/BuildNumber
# - Heuristic KB/patch matching via configurable database (example entries included)
# - Output: JSON, CSV, HTML
# - CLI: -t (targets), -c (concurrency), -o (output), -f (format json/csv/html), -timeout, -retries, -proxy, -about
# - Supports single IP, comma-separated list, @file, and CIDR ranges (e.g., 10.0.0.0/24)
# - Uses only non-destructive GET/POST read-only SOAP calls. No payloads or exploit actions.
# Save as wsus_scanner_enhanced.py and run with Python 3.8+

import argparse
import requests
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json, csv, html
import sys, time, ipaddress, io
from typing import List, Dict

# -------- Configuration (tune if needed) --------
DEFAULT_CONCURRENCY = 40
DEFAULT_TIMEOUT = 6
DEFAULT_RETRIES = 1
VERIFY_SSL = False
USER_AGENT = "ACyber-WSUS-Scanner/1.1"
SOAP_GET_ROLLUP = b"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetRollupConfiguration xmlns="http://www.microsoft.com/SoftwareDistribution">
      <cookie xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"/>
    </GetRollupConfiguration>
  </soap:Body>
</soap:Envelope>
"""

# Example KB/patch DB (user extendable). Mapping: (major_version, build_prefix) -> {"kb": ["KBxxxx"], "patched_after_build": <int>}
# This is illustrative. Real mappings require authoritative KB/build data.
KB_DB = [
    {"os":"WSUS", "major":"10.0", "build_prefix":"17763", "kb":["KB5003173"], "patched_after_build":17763},  # example
    {"os":"WSUS", "major":"10.0", "build_prefix":"19041", "kb":["KB5009543"], "patched_after_build":19041},
]

# -------- Helpers --------
def requests_session(proxy=None, retries=1):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    # simple retry loop implemented in caller
    return s

def is_text_xml(resp):
    ct = (resp.headers.get("Content-Type") or "").lower()
    return "xml" in ct or "soap" in (resp.text or "").lower()

def extract_server_fields_from_soap(body: str) -> Dict[str,str]:
    """Try to parse SOAP XML and extract ServerId, ServerVersion, BuildNumber etc.
       Returns a dict of found fields (strings)."""
    res = {}
    if not body:
        return res
    try:
        # Use ET to parse; ignore namespaces by reading itertext and searching markers
        root = ET.fromstring(body)
        text = ''.join(root.itertext())
        # naive extractions
        if "ServerId" in body:
            # attempt parse between tags
            if "<ServerId" in body:
                try:
                    sid = body.split("<ServerId")[1].split(">")[1].split("<")[0].strip()
                    res["ServerId"] = sid
                except Exception:
                    pass
        # Try to find common version/build tokens
        for key in ["ServerVersion", "BuildNumber", "ServerVersionString"]:
            if key in text:
                # crude extraction: find key followed by digits
                import re
                m = re.search(rf"{key}[^0-9]*([0-9]+(\.[0-9]+)*)", text, re.IGNORECASE)
                if m:
                    res[key] = m.group(1)
        # Also try to find 'Version' or 'ProductVersion' tokens
        import re
        m = re.search(r"(Version|ProductVersion)[^0-9]*(\d+(\.\d+)+)", text, re.IGNORECASE)
        if m and "Version" not in res:
            res["Version"] = m.group(2)
    except Exception:
        pass
    return res

def guess_patch_status(fields: Dict[str,str]) -> Dict[str,str]:
    """Heuristic mapping from extracted fields to patched/vulnerable suggestion."""
    guess = {"status":"unknown", "matched_kb":[]}
    # check ServerVersion or Version
    ver = fields.get("ServerVersion") or fields.get("Version") or fields.get("ServerVersionString") or ""
    build = fields.get("BuildNumber") or ""
    try:
        # try to parse numeric build if present
        bnum = int(''.join(ch for ch in build if ch.isdigit())) if build else None
    except Exception:
        bnum = None

    for entry in KB_DB:
        mprefix = entry.get("build_prefix","")
        if mprefix and build.startswith(mprefix):
            guess["status"] = "maybe_vulnerable" if (bnum and bnum <= entry.get("patched_after_build", 0)) else "maybe_patched"
            guess["matched_kb"] = entry.get("kb", [])
            return guess

    # fallback heuristics
    if ver:
        if ver.startswith("10"):
            guess["status"] = "unknown_but_wsus_10x"
        else:
            guess["status"] = "unknown"
    else:
        guess["status"] = "unknown_no_version"

    return guess

# -------- Core checking --------
def safe_get(session, url, timeout, verify):
    for _ in range(0, session.retries if hasattr(session,'retries') else 1):
        try:
            r = session.get(url, timeout=timeout, verify=verify)
            return r
        except Exception:
            time.sleep(0.1)
    return None

def safe_post(session, url, data, soap_action, timeout, verify):
    headers = {"Content-Type":"text/xml; charset=utf-8", "SOAPAction": soap_action}
    for _ in range(0, session.retries if hasattr(session,'retries') else 1):
        try:
            r = session.post(url, data=data, headers=headers, timeout=timeout, verify=verify)
            return r
        except Exception:
            time.sleep(0.1)
    return None

def check_host(target: str, timeout: int, retries: int, proxy: str, verify_ssl: bool) -> Dict:
    result = {"target": target, "ports": {}, "reachable": False}
    session = requests_session(proxy=proxy, retries=retries)
    session.retries = max(1, retries)
    for port, scheme in [(8530,"http"), (8531,"https")]:
        port_info = {"open": False, "endpoints":{}, "server_fields":{}, "patch_guess":{}}
        base = f"{scheme}://{target}:{port}"
        # 1) cheap GET to base
        try:
            r = session.get(base, timeout=timeout, verify=verify_ssl)
        except Exception:
            r = None
        if r and r.status_code == 200:
            port_info["open"] = True
            result["reachable"] = True
            port_info["server_header"] = r.headers.get("Server")
        # 2) check endpoints (GET)
        endpoints = {
            "report": "/ReportingWebService/ReportingWebService.asmx",
            "auth": "/SimpleAuthWebService/SimpleAuth.asmx",
            "client": "/ClientWebService/Client.asmx"
        }
        for k,p in endpoints.items():
            try:
                r2 = session.get(base + p, timeout=timeout, verify=verify_ssl)
            except Exception:
                r2 = None
            if r2 and r2.status_code == 200 and (is_text_xml(r2) or "<soap" in (r2.text or "").lower()):
                port_info["endpoints"][k] = True
                # attempt to extract version tokens from WSDL/body
                fields = extract_server_fields_from_soap(r2.text)
                if fields:
                    port_info["server_fields"].update(fields)
        # 3) safe SOAP POST to report/GetRollupConfiguration if report endpoint present
        if port_info["endpoints"].get("report"):
            report_url = base + "/ReportingWebService/ReportingWebService.asmx"
            r3 = safe_post(session, report_url, SOAP_GET_ROLLUP, "http://www.microsoft.com/SoftwareDistribution/GetRollupConfiguration", timeout, verify_ssl)
            if r3 and r3.status_code == 200:
                port_info["endpoints"]["getrollup_ok"] = True
                fields = extract_server_fields_from_soap(r3.text)
                if fields:
                    port_info["server_fields"].update(fields)
        # 4) Guess patch status
        port_info["patch_guess"] = guess_patch_status(port_info["server_fields"])
        result["ports"][str(port)] = port_info
    return result

# -------- Target parsing (supports single, comma, @file, CIDR) --------
def expand_targets(arg: str) -> List[str]:
    arg = arg.strip()
    if arg.startswith("@"):
        path = arg[1:]
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Targets file not found: {path}")
        lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
        out = []
        for l in lines:
            out += expand_targets(l)
        return list(dict.fromkeys(out))
    if "/" in arg:  # CIDR
        net = ipaddress.ip_network(arg, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "," in arg:
        return [a.strip() for a in arg.split(",") if a.strip()]
    return [arg]

# -------- Output formats --------
def save_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def save_csv(results, path):
    # Flatten results for CSV: target,port,open,report,auth,client,getrollup,server_fields_json,patch_guess_status,matched_kb
    rows = []
    for r in results:
        t = r.get("target")
        for port, info in r.get("ports", {}).items():
            rows.append({
                "target": t,
                "port": port,
                "open": info.get("open", False),
                "report": info.get("endpoints", {}).get("report", False),
                "auth": info.get("endpoints", {}).get("auth", False),
                "client": info.get("endpoints", {}).get("client", False),
                "getrollup_ok": info.get("endpoints", {}).get("getrollup_ok", False),
                "server_fields": json.dumps(info.get("server_fields", {}), ensure_ascii=False),
                "patch_status": info.get("patch_guess", {}).get("status"),
                "matched_kb": ",".join(info.get("patch_guess", {}).get("matched_kb", []))
            })
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ["target","port","open"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def save_html(results, path):
    # Simple HTML table
    html_rows = []
    for r in results:
        t = r.get("target")
        for port, info in r.get("ports", {}).items():
            status = info.get("patch_guess", {}).get("status", "unknown")
            matched = ",".join(info.get("patch_guess", {}).get("matched_kb", []))
            sf = html.escape(json.dumps(info.get("server_fields", {}), ensure_ascii=False))
            html_rows.append(f"<tr><td>{t}</td><td>{port}</td><td>{info.get('open')}</td><td>{info.get('endpoints', {}).get('report',False)}</td><td>{status}</td><td>{matched}</td><td><pre>{sf}</pre></td></tr>")
    page = f"""<html><head><meta charset="utf-8"><title>WSUS Scan Results</title></head><body>
    <h2>WSUS Scan Results</h2>
    <table border="1" cellspacing="0" cellpadding="4">
    <tr><th>Target</th><th>Port</th><th>Open</th><th>Report</th><th>PatchGuess</th><th>MatchedKB</th><th>ServerFields</th></tr>
    {''.join(html_rows)}
    </table>
    </body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)

# -------- Runner --------
def run_scan(target_arg: str, concurrency: int, timeout: int, retries: int, proxy: str, out_path: str, out_format: str, verify_ssl: bool):
    targets = []
    # expand comma separated within argument list e.g., -t a,b -t c
    if isinstance(target_arg, list):
        for t in target_arg:
            targets += expand_targets(t)
    else:
        targets = expand_targets(target_arg)
    targets = list(dict.fromkeys(targets))  # dedupe preserving order
    print(f"[+] {len(targets)} targets expanded. Concurrency={concurrency} Timeout={timeout}s Retries={retries}")
    results = []
    session_template = requests_session(proxy=proxy, retries=retries)

    with ThreadPoolExecutor(max_workers=concurrency) as exe:
        futures = {exe.submit(check_host, t, timeout, retries, proxy, verify_ssl): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"target": t, "error": str(e)}
            results.append(res)
            # print minimal summary line
            line = []
            if res.get("reachable"):
                for port, info in res.get("ports", {}).items():
                    status = info.get("patch_guess", {}).get("status", "unknown")
                    label = "POTENTIAL_VULN" if status == "maybe_vulnerable" else status.upper()
                    line.append(f"{port}:{label}")
            else:
                line.append("UNREACHABLE")
            print(f"[{t}] " + " | ".join(line))
    # outputs
    if out_path:
        out_format = out_format.lower()
        if out_format == "json":
            save_json(results, out_path)
        elif out_format == "csv":
            save_csv(results, out_path)
        elif out_format == "html":
            save_html(results, out_path)
        else:
            save_json(results, out_path)
        print(f"[+] Results saved to {out_path} ({out_format})")
    return results

def about():
    print("ACyber WSUS Passive Scanner — Enhanced")
    print("Author: mrmtwoj")
    print("Contact: acyber.ir    github: @mrmtwoj")
    print("Safe, non-destructive scanner for WSUS endpoints. Does NOT attempt exploitation.\n")

# -------- CLI --------
def main():
    parser = argparse.ArgumentParser(prog="wsus_scanner_enhanced.py", description="WSUS Passive Scanner — safe. Use -about for credits.")
    parser.add_argument("-t", "--targets", required=False, nargs="+", help="Targets: IP, comma-separated, CIDR (10.0.0.0/24), or @file. You may pass multiple -t flags.")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Worker threads")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Number of retries for network ops")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Output file path (use extension .json/.csv/.html or specify -f)")
    parser.add_argument("-f", "--format", choices=["json","csv","html"], default="json", help="Output format")
    parser.add_argument("-about", action="store_true", help="Show about info")
    args = parser.parse_args()

    if args.about:
        about()
        return

    if not args.targets:
        parser.print_help()
        return

    try:
        results = run_scan(args.targets, args.concurrency, args.timeout, args.retries, args.proxy, args.output, args.format, VERIFY_SSL)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
print("Module loaded. Save this file as wsus_scanner_enhanced.py and run with Python 3.")