"""Single-URL, passive web security header review for authorized use."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

TIMEOUT_SECONDS = 10
USER_AGENT = "StudentSecurityHeaderScanner/1.0 (educational; single-request)"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def validate_url(url: str) -> str:
    value = url.strip()
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Enter an absolute URL beginning with http:// or https://")
    if parts.username or parts.password:
        raise ValueError("Do not include credentials in the URL")
    return value

def header(headers: Mapping[str, str], name: str):
    return next((str(v).strip() for k, v in headers.items() if k.lower() == name.lower()), None)

def evaluate_headers(headers: Mapping[str, str], url: str) -> list[dict[str, str]]:
    h = dict(headers)
    https = urlsplit(url).scheme.lower() == "https"
    findings = []
    def add(check, status, observed, guidance):
        findings.append({"check": check, "status": status, "observed": observed, "guidance": guidance})
    hsts = header(h, "Strict-Transport-Security")
    add("HSTS", ("Present" if hsts else "Not observed") if https else "Not assessed",
        hsts or ("Header not present" if https else "URL uses HTTP"),
        "Review HSTS on the canonical HTTPS site; includeSubDomains only if all subdomains support HTTPS.")
    csp = header(h, "Content-Security-Policy")
    add("Content Security Policy", "Present" if csp else "Not observed", csp or "Header not present",
        "Review a policy suited to the application; report-only mode can help during rollout.")
    xcto = header(h, "X-Content-Type-Options")
    add("Content type sniffing", "Present" if xcto and xcto.lower() == "nosniff" else ("Review" if xcto else "Not observed"),
        xcto or "Header not present", "For typical web content, consider X-Content-Type-Options: nosniff.")
    xfo = header(h, "X-Frame-Options")
    framed = bool(csp and "frame-ancestors" in csp.lower())
    add("Framing protection", "Present" if (xfo or framed) else "Not observed",
        "; ".join(x for x in ([f"X-Frame-Options: {xfo}" if xfo else "", "CSP frame-ancestors observed" if framed else ""]) if x)
        or "Neither X-Frame-Options nor CSP frame-ancestors observed",
        "Choose framing rules based on whether trusted pages need to embed this site.")
    for name, label, guidance in [
        ("Referrer-Policy", "Referrer policy", "Limit referrer data while meeting application needs."),
        ("Permissions-Policy", "Browser feature policy", "Restrict browser features the application does not need.")]:
        value = header(h, name)
        add(label, "Present" if value else "Not observed", value or "Header not present", guidance)
    cors = header(h, "Access-Control-Allow-Origin")
    creds = header(h, "Access-Control-Allow-Credentials")
    if cors is None:
        status, observed = "Not observed", "No Access-Control-Allow-Origin in this response"
    elif cors == "*":
        status, observed = "Review", "Wildcard origin observed; impact depends on resource and data"
    else:
        status, observed = "Present", cors
    if cors == "*" and creds and creds.lower() == "true":
        status = "Review"
        observed += "; credentials=true also observed (browsers reject wildcard origin with credentials)"
    add("CORS response header", status, observed,
        "Allow only required origins. This single response check does not test Origin-specific behavior.")
    server, powered = header(h, "Server"), header(h, "X-Powered-By")
    disclosure = "; ".join(x for x in ([f"Server: {server}" if server else "",
                                       f"X-Powered-By: {powered}" if powered else ""]) if x)
    add("Technology disclosure", "Review" if disclosure else "Not observed",
        disclosure or "No common disclosure header observed",
        "Avoid detailed software version disclosure when it is not needed.")
    return findings

def scan_url(url: str, authorized: bool = False) -> dict:
    if not authorized:
        raise PermissionError("Confirm authorization before scanning.")
    safe_url = validate_url(url)
    req = Request(safe_url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}, method="GET")
    status, final_url, response_headers, error = None, safe_url, {}, None
    try:
        with build_opener(NoRedirect).open(req, timeout=TIMEOUT_SECONDS) as response:
            status, final_url = response.status, response.geturl()
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        status, final_url = exc.code, exc.geturl()
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        exc.close()
    except (URLError, TimeoutError, OSError) as exc:
        error = f"Request failed: {exc}"
    result = {"requested_url": safe_url, "final_url": final_url,
              "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "status_code": status, "error": error, "findings": []}
    if not error:
        result["findings"] = evaluate_headers(response_headers, final_url)
    return result

def print_report(result: dict) -> None:
    print("\nAUTOMATED WEB SECURITY HEADER SCANNER")
    print("=" * 42)
    for label, key in [("Requested URL", "requested_url"), ("Final URL", "final_url"),
                       ("Checked UTC", "timestamp_utc"), ("HTTP status", "status_code")]:
        print(f"{label}: {result[key]}")
    if result["error"]:
        print(result["error"])
        return
    for f in result["findings"]:
        print(f"\n[{f['status']}] {f['check']}\n  Observed: {f['observed']}\n  Guidance: {f['guidance']}")
    if result["status_code"] and 300 <= result["status_code"] < 400:
        print("Redirect was not followed. Review its destination manually and scan it only if authorized.")
    print("\nInformational review only. Confirm observations with the site owner and application context.")

def main():
    parser = argparse.ArgumentParser(description="Passively review headers for one authorized URL.")
    parser.add_argument("url", nargs="?", help="One URL you own or may assess")
    args = parser.parse_args()
    url = args.url or input("Enter one authorized HTTP(S) URL: ").strip()
    if input("This sends one GET request. Do you own this site or have permission? Type YES: ").strip() != "YES":
        raise SystemExit("Stopped. No request was sent.")
    try:
        print_report(scan_url(url, authorized=True))
    except (ValueError, PermissionError) as exc:
        raise SystemExit(str(exc)) from exc

if __name__ == "__main__":
    main()
