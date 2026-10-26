# Automated Web Scanner

**Author:** Kiruthika
**Course:** BE Cyber Security, Sona College of Technology, Salem

A lightweight command-line tool that audits a URL for missing or weak HTTP security headers and for common CORS misconfigurations.

## Project Description

The scanner sends a normal GET request to the target and inspects the response headers, then sends a few extra requests with crafted `Origin` headers to see how the server handles cross-origin access. Findings are grouped into two sections in the terminal output and rated HIGH, MEDIUM or LOW.

**Security headers checked**

| Header | What is flagged |
|---|---|
| Strict-Transport-Security | missing, `max-age=0`, short max-age, no `includeSubDomains`, page served over HTTP |
| Content-Security-Policy | missing, `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`/`http:` sources, no `script-src`/`default-src`, no `object-src` |
| X-Frame-Options | missing (and no CSP `frame-ancestors`), or a value other than `DENY`/`SAMEORIGIN` |
| X-Content-Type-Options | missing or not `nosniff` |
| Referrer-Policy | missing, `unsafe-url`, `no-referrer-when-downgrade` |

**CORS checks (active)**

- Reflective origin: `Origin: https://attacker.com` echoed back in `Access-Control-Allow-Origin`
- Wildcard `*` combined with `Access-Control-Allow-Credentials: true`
- Null origin reflection: `Origin: null`
- Lookalike-domain bypass (`https://<target-host>.attacker.com`), which catches weak suffix/prefix validation
- Reflected origin without `Vary: Origin` (cache poisoning risk)

## Technologies Used

- Python 3.8+
- `requests` for HTTP
- `argparse` and `urllib.parse` from the standard library
- `colorama` for coloured terminal output

## Dataset

Not applicable. The tool works on live HTTP responses and uses no dataset.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python Kiruthika_AutomatedWebScanner.py https://example.com
python Kiruthika_AutomatedWebScanner.py example.com -t 5
python Kiruthika_AutomatedWebScanner.py https://self-signed.local -k
```

| Option | Meaning |
|---|---|
| `url` | Target URL. `https://` is assumed if no scheme is given |
| `-t`, `--timeout` | Request timeout in seconds (default 10) |
| `-k`, `--insecure` | Skip TLS certificate verification |

Exit codes: `0` when no HIGH finding is reported, `1` when at least one HIGH finding is reported, and `2` for errors such as an invalid URL, a timeout or a connection failure. This makes the tool usable in a CI pipeline.

## Key Information

- **Authorised use only.** The CORS checks send crafted requests to the target. Scan only systems you own or have written permission to test.
- Results are indicators, not proof of exploitability. For example, a reflected origin on a public, unauthenticated endpoint is much less serious than one on an endpoint that returns user data.
- Only the given URL is tested, so headers and CORS policy on other paths or subdomains can differ.
- The tool makes about five requests per scan and does no crawling or fuzzing.
