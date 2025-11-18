
"""Scanner for Concept B with optional Nmap and Nikto integrations.

Usage examples:
  python src/scanner.py --url "https://example.com?q=test" --dry-run
  python src/scanner.py --url "https://example.com?q=test" --use-nmap --use-nikto
"""
import argparse
import re
import requests
import subprocess
from urllib.parse import urlparse, parse_qs

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "sql syntax error",
    "mysql",
    "syntax error",
]
SENSITIVE_PATTERNS = [re.compile(r"api[_-]?key", re.I), re.compile(r"password", re.I), re.compile(r"secret", re.I)]
DEFAULT_TIMEOUT = 8.0

def fetch(url, params=None, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(url, params=params, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None

def check_reflected_xss(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    results = []
    if not qs:
        return results
    payload = "<script>alert(1)</script>"
    for k in qs.keys():
        params = {kk: vv[0] for kk, vv in qs.items()}
        params[k] = payload
        base = parsed._replace(query=None).geturl()
        r = fetch(base, params=params)
        if r and payload in r.text:
            results.append({"type": "XSS (reflected)", "param": k, "evidence": payload})
    return results

def check_sql_injection(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    results = []
    if not qs:
        return results
    payloads = ["'", '"', "' OR '1'='1", "' OR 1=1 -- "]
    for k in qs.keys():
        base_params = {kk: vv[0] for kk, vv in qs.items()}
        for p in payloads:
            params = {**base_params, k: base_params.get(k, '') + p}
            r = fetch(parsed._replace(query=None).geturl(), params=params)
            if r:
                body = r.text.lower()
                if any(e in body for e in SQL_ERRORS):
                    results.append({"type": "SQL Injection (heuristic)", "param": k, "payload": p})
    return results

def check_directory_traversal(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    results = []
    traversal = ['../../../../etc/passwd', '..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts']
    for k in qs.keys():
        base_params = {kk: vv[0] for kk, vv in qs.items()}
        for t in traversal:
            params = {**base_params, k: t}
            r = fetch(parsed._replace(query=None).geturl(), params=params)
            if r and ("root:x:" in r.text or "127.0.0.1" in r.text):
                results.append({"type": "Directory Traversal", "param": k, "evidence": "etc/passwd or hosts"})
    return results

def check_sensitive_exposure(url):
    r = fetch(url)
    results = []
    if not r:
        return results
    for patt in SENSITIVE_PATTERNS:
        if patt.search(r.text):
            results.append({"type": "Sensitive Data Exposure", "pattern": patt.pattern})
    return results

def run_nmap(target, timeout=180):
    try:
        cmd = [
            "nmap",
            "-Pn",                 # pula host discovery (útil se ICMP bloqueado)
            "-p", "80,443,8080",   # varre apenas portas comuns — muito mais rápido
            "-sT",                 # TCP connect (não-requer root)
            "-T4",                 # agressividade
            "--max-retries", "2",
            "--host-timeout", "3m",
            target
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"type": "nmap", "target": target, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"type": "nmap", "error": "nmap not installed"}
    except Exception as e:
        return {"type": "nmap", "error": str(e)}


def run_nikto(target, timeout=300):
    try:
        cmd = ["nikto", "-h", target, "-timeout", "10", "-maxtime", "300", "-Tuning", "1"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"type": "nikto", "target": target, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"type": "nikto", "error": "nikto not installed"}
    except Exception as e:
        return {"type": "nikto", "error": str(e)}


def run_external_scans(url, use_nmap=False, use_nikto=False, dry_run=False):
    results = []
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return results
    if dry_run:
        if use_nmap:
            results.append({"type": "nmap", "note": "dry-run: skipped nmap"})
        if use_nikto:
            results.append({"type": "nikto", "note": "dry-run: skipped nikto"})
        return results
    if use_nmap:
        results.append(run_nmap(host))
    if use_nikto:
        results.append(run_nikto(url))
    return results

def run_scan(url, dry_run=False, use_nmap=False, use_nikto=False):
    out = {"url": url, "vulnerabilities": [], "external_scans": []}
    if dry_run:
        out["note"] = "dry-run: no live checks performed"
        out["external_scans"] = run_external_scans(url, use_nmap=use_nmap, use_nikto=use_nikto, dry_run=True)
        return out
    out["vulnerabilities"].extend(check_reflected_xss(url))
    out["vulnerabilities"].extend(check_sql_injection(url))
    out["vulnerabilities"].extend(check_directory_traversal(url))
    out["vulnerabilities"].extend(check_sensitive_exposure(url))
    out["external_scans"] = run_external_scans(url, use_nmap=use_nmap, use_nikto=use_nikto, dry_run=False)
    return out

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--dry-run', action='store_true', help='Do not perform live HTTP requests; useful for CI')
    parser.add_argument('--use-nmap', action='store_true', help='Run nmap against the host (requires nmap installed)')
    parser.add_argument('--use-nikto', action='store_true', help='Run nikto against the target (requires nikto installed)')
    args = parser.parse_args()
    result = run_scan(args.url, dry_run=args.dry_run, use_nmap=args.use_nmap, use_nikto=args.use_nikto)
    print(result)
