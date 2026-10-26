#!/usr/bin/env python3
import argparse
import re
import sys
from urllib.parse import urlparse

import requests
import urllib3
from colorama import Fore, Style, init

init(autoreset=True)

COLORS = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}
HSTS_MIN_AGE = 15552000  # 180 days
WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


def normalize_url(raw):
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid URL: {raw}")
    return raw


def send_request(url, timeout, verify, origin=None):
    headers = {"User-Agent": "web-scanner/1.0"}
    if origin is not None:
        headers["Origin"] = origin
    return requests.get(url, headers=headers, timeout=timeout, verify=verify)


def parse_csp(value):
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def check_hsts(resp):
    if resp.url.startswith("http://"):
        return [("HIGH", "Page served over plain HTTP, HSTS has no effect")]
    value = resp.headers.get("Strict-Transport-Security")
    if not value:
        return [("HIGH", "Strict-Transport-Security missing")]
    match = re.search(r"max-age=(\d+)", value, re.I)
    if not match:
        return [("MEDIUM", f"HSTS has no max-age: {value}")]
    max_age = int(match.group(1))
    findings = []
    if max_age == 0:
        findings.append(("HIGH", "HSTS max-age=0 disables the policy"))
    elif max_age < HSTS_MIN_AGE:
        findings.append(("LOW", f"HSTS max-age too short ({max_age}s, want >= {HSTS_MIN_AGE}s)"))
    if "includesubdomains" not in value.lower():
        findings.append(("LOW", "HSTS missing includeSubDomains"))
    return findings


def check_csp(headers):
    value = headers.get("Content-Security-Policy")
    if not value:
        return [("HIGH", "Content-Security-Policy missing")]
    directives = parse_csp(value)
    findings = []
    script_src = directives.get("script-src", directives.get("default-src"))
    if script_src is None:
        findings.append(("MEDIUM", "CSP defines neither script-src nor default-src"))
    else:
        # a nonce or hash makes browsers ignore 'unsafe-inline', so it's only dangerous alone
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script_src)
        if "'unsafe-inline'" in script_src and not has_nonce:
            findings.append(("HIGH", "CSP script-src allows 'unsafe-inline'"))
        if "'unsafe-eval'" in script_src:
            findings.append(("MEDIUM", "CSP script-src allows 'unsafe-eval'"))
        if "*" in script_src:
            findings.append(("HIGH", "CSP script-src allows any origin (*)"))
        if "data:" in script_src or "http:" in script_src:
            findings.append(("MEDIUM", "CSP script-src allows data: or http: sources"))
    if "object-src" not in directives and "default-src" not in directives:
        findings.append(("LOW", "CSP missing object-src (plugin content not restricted)"))
    return findings


def check_xfo(headers):
    value = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")
    # frame-ancestors supersedes X-Frame-Options in modern browsers
    if not value:
        if "frame-ancestors" in parse_csp(csp):
            return []
        return [("MEDIUM", "X-Frame-Options missing and no CSP frame-ancestors (clickjacking)")]
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [("LOW", f"X-Frame-Options has weak/obsolete value: {value}")]
    return []


def check_nosniff(headers):
    value = headers.get("X-Content-Type-Options")
    if not value:
        return [("MEDIUM", "X-Content-Type-Options missing")]
    if value.strip().lower() != "nosniff":
        return [("LOW", f"X-Content-Type-Options should be 'nosniff', got: {value}")]
    return []


def check_referrer(headers):
    value = headers.get("Referrer-Policy")
    if not value:
        return [("LOW", "Referrer-Policy missing")]
    # last valid token wins when multiple are listed
    policy = value.split(",")[-1].strip().lower()
    if policy in WEAK_REFERRER:
        return [("MEDIUM", f"Referrer-Policy leaks full URL cross-origin: {policy}")]
    return []


def audit_headers(resp):
    findings = check_hsts(resp)
    for check in (check_csp, check_xfo, check_nosniff, check_referrer):
        findings += check(resp.headers)
    return findings


def probe_cors(url, origin, timeout, verify):
    resp = send_request(url, timeout, verify, origin=origin)
    allow_origin = resp.headers.get("Access-Control-Allow-Origin")
    allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    vary = resp.headers.get("Vary", "").lower()
    return allow_origin, allow_creds, "origin" in vary or vary == "*"


def audit_cors(url, timeout, verify):
    host = urlparse(url).hostname
    findings = []

    evil = "https://attacker.com"
    allow_origin, creds, vary_origin = probe_cors(url, evil, timeout, verify)
    reflected_evil = allow_origin == evil
    if reflected_evil:
        severity = "HIGH" if creds else "MEDIUM"
        suffix = " with credentials allowed" if creds else ""
        findings.append((severity, f"Arbitrary origin reflected{suffix}"))
        if not vary_origin:
            # caches may serve one origin's ACAO to another
            findings.append(("LOW", "Reflected ACAO without 'Vary: Origin' (cache poisoning risk)"))
    elif allow_origin == "*":
        if creds:
            # browsers reject this combo, but it shows the server is configured blindly
            findings.append(("HIGH", "Wildcard ACAO combined with Allow-Credentials: true"))
        else:
            findings.append(("LOW", "Wildcard ACAO (fine only for fully public data)"))

    # sandboxed iframes and data: URLs send Origin: null, so trusting it is trusting any attacker page
    allow_origin, creds, _ = probe_cors(url, "null", timeout, verify)
    if allow_origin == "null":
        severity = "HIGH" if creds else "MEDIUM"
        suffix = " with credentials allowed" if creds else ""
        findings.append((severity, f"Null origin reflected{suffix}"))

    # catches naive startswith/regex validation of the trusted domain
    if not reflected_evil:
        bypass = f"https://{host}.attacker.com"
        allow_origin, creds, _ = probe_cors(url, bypass, timeout, verify)
        if allow_origin == bypass:
            severity = "HIGH" if creds else "MEDIUM"
            findings.append((severity, f"Origin validation bypassable via lookalike domain ({bypass})"))

    return findings


def print_section(title, findings):
    print(f"\n{Style.BRIGHT}{title}")
    print("-" * len(title))
    if not findings:
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} no issues found")
        return
    for severity, message in findings:
        print(f"{COLORS[severity]}[{severity:<6}]{Style.RESET_ALL} {message}")


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def parse_args():
    parser = argparse.ArgumentParser(description="Audit a URL for weak security headers and CORS misconfigurations.")
    parser.add_argument("url", help="target URL, e.g. https://example.com")
    parser.add_argument("-t", "--timeout", type=float, default=10, help="request timeout in seconds (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS certificate verification")
    return parser.parse_args()


def main():
    args = parse_args()
    verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        url = normalize_url(args.url)
        resp = send_request(url, args.timeout, verify)
        header_findings = audit_headers(resp)
        cors_findings = audit_cors(resp.url, args.timeout, verify)
    except ValueError as err:
        fail(f"{err}")
    except requests.exceptions.SSLError:
        fail("TLS verification failed (use -k to skip)")
    except requests.exceptions.Timeout:
        fail(f"request timed out after {args.timeout}s")
    except requests.exceptions.ConnectionError as err:
        fail(f"could not connect: {err}")
    except requests.exceptions.RequestException as err:
        fail(f"{err}")

    print(f"Target: {resp.url}  [{resp.status_code}]")
    print_section("Missing/Weak Headers", header_findings)
    print_section("CORS Vulnerabilities", cors_findings)

    if any(severity == "HIGH" for severity, _ in header_findings + cors_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
