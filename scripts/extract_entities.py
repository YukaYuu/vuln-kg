"""Extract structured entities from CVE free-text descriptions (English) using an LLM.

Schema:
  component         The affected software component (as named in the free text --
                     not guaranteed to match the CPE product name, which is exactly
                     the value this free-text extraction adds).
  vulnerability_type The kind of vulnerability (free text; sometimes more specific
                     than the CWE).
  attack_vector      A short description of how it's exploited.
  requires_auth      Whether exploitation requires authentication (false / true /
                     "local", etc., as a free-text qualifier).

These 24 entries were extracted by manually reading each CVE description, following
the schema above, rather than through a live API call (no LLM API key was available in
this environment). The same prompt and schema could be used to automate this via an
LLM API call in production.

Usage: this file doubles as the data file holding the extraction results (EXTRACTED).
Output: data/extracted_entities.json (written by python scripts/extract_entities.py)
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"

EXTRACTED = {
    "CVE-2024-39693": {"component": "Next.js", "vulnerability_type": "denial of service", "attack_vector": "crafted request triggers server crash", "requires_auth": False},
    "CVE-2024-37162": {"component": "zsa (Next.js server actions library)", "vulnerability_type": "information disclosure", "attack_vector": "parse error stack leaks server env info to client in production build", "requires_auth": False},
    "CVE-2024-34351": {"component": "Next.js Server Actions", "vulnerability_type": "server-side request forgery (SSRF)", "attack_vector": "modified Host header combined with self-hosted Server Action redirect to relative path", "requires_auth": False},
    "CVE-2024-34350": {"component": "Next.js", "vulnerability_type": "HTTP request smuggling / response queue poisoning", "attack_vector": "crafted HTTP request interpreted inconsistently when using rewrites", "requires_auth": False},
    "CVE-2024-29901": {"component": "AuthKit library for Next.js", "vulnerability_type": "session/authentication bypass", "attack_vector": "reuse of expired session via controlling x-workos-session header", "requires_auth": False},
    "CVE-2024-23841": {"component": "@apollo/experimental-apollo-client-nextjs", "vulnerability_type": "cross-site scripting (XSS)", "attack_vector": "malicious input via redirect link or persisted GraphQL server response", "requires_auth": False},
    "CVE-2023-48309": {"component": "next-auth (NextAuth.js)", "vulnerability_type": "authentication bypass (mock user)", "attack_vector": "interrupted OAuth sign-in JWT reused to override session cookie", "requires_auth": False},
    "CVE-2023-46729": {"component": "@sentry/nextjs tunnel endpoint", "vulnerability_type": "open proxy / SSRF-like", "attack_vector": "unsanitized tunnel endpoint input forwards requests to arbitrary URLs", "requires_auth": False},

    "CVE-2016-7191": {"component": "passport-azure-ad (Node.js)", "vulnerability_type": "authentication bypass", "attack_vector": "validateIssuer setting not honored, crafted token", "requires_auth": False},
    "CVE-2016-7099": {"component": "Node.js tls.checkServerIdentity", "vulnerability_type": "certificate validation flaw (MITM)", "attack_vector": "crafted X.509 certificate with wildcard in name field", "requires_auth": False},
    "CVE-2016-5325": {"component": "Node.js http ServerResponse#writeHead", "vulnerability_type": "CRLF injection / HTTP response splitting", "attack_vector": "crafted reason argument", "requires_auth": False},
    "CVE-2016-3956": {"component": "npm CLI (Node.js)", "vulnerability_type": "information disclosure", "attack_vector": "bearer tokens sent with arbitrary requests, exposed via Authorization header", "requires_auth": False},
    "CVE-2016-2537": {"component": "is-my-json-valid (Node.js package)", "vulnerability_type": "denial of service (ReDoS)", "attack_vector": "crafted string matches inefficient regex, blocks event loop", "requires_auth": False},
    "CVE-2016-2216": {"component": "Node.js HTTP header parser", "vulnerability_type": "HTTP response-splitting protection bypass", "attack_vector": "UTF-8 encoded Unicode characters in HTTP header", "requires_auth": False},
    "CVE-2016-2086": {"component": "Node.js HTTP parser", "vulnerability_type": "HTTP request smuggling", "attack_vector": "crafted Content-Length header", "requires_auth": False},
    "CVE-2016-1202": {"component": "Atom Electron", "vulnerability_type": "untrusted search path / privilege escalation", "attack_vector": "Trojan horse Node.js module placed in parent directory of required module", "requires_auth": "local user required"},

    "CVE-2001-1468": {"component": "phpSecurePages checklogin.php", "vulnerability_type": "remote file inclusion", "attack_vector": "cfgProgDir parameter modified to reference remote code URL", "requires_auth": False},
    "CVE-2001-1385": {"component": "PHP Apache module", "vulnerability_type": "misconfiguration / information disclosure", "attack_vector": "engine=off on one virtual host disables PHP for others, exposing source", "requires_auth": False},
    "CVE-2001-1363": {"component": "phpWebSite", "vulnerability_type": "privilege escalation", "attack_vector": "running multiple instances in same domain", "requires_auth": False},
    "CVE-2001-1358": {"component": "phpMyChat", "vulnerability_type": "privilege escalation / local file inclusion", "attack_vector": "alternate library file specified via L (localization) parameter", "requires_auth": "local or possibly remote"},
    "CVE-2001-1357": {"component": "phpMyChat (input.php3 etc.)", "vulnerability_type": "unknown / user spoofing", "attack_vector": "improperly initialized variables in multiple scripts", "requires_auth": "unclear"},
    "CVE-2001-1246": {"component": "PHP mail() function (safe mode)", "vulnerability_type": "command injection", "attack_vector": "shell metacharacters in 5th parameter of mail()", "requires_auth": "local user, possibly remote"},
    "CVE-2001-1159": {"component": "SquirrelMail load_prefs.php", "vulnerability_type": "information disclosure / remote code execution", "attack_vector": "improperly initialized PHP variables via config_php/data_dir options, malicious upload via options_order.php", "requires_auth": False},
    "CVE-2001-0479": {"component": "phpPgAdmin sql.php", "vulnerability_type": "directory traversal / remote code execution", "attack_vector": "dot-dot sequence in script argument", "requires_auth": False},
}


def main():
    out_path = DATA / "extracted_entities.json"
    out_path.write_text(json.dumps(EXTRACTED, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Saved {len(EXTRACTED)} entries: {out_path}")


if __name__ == "__main__":
    main()
