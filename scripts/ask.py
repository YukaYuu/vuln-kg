"""A minimal natural-language-ish front end that turns a question into a graph query.

Patterns handled:
  "Which service does CVE-XXXX-XXXXX affect?" -> calls query_impact.impact()
  "Which CVEs affect <service name>?"         -> reverse lookup (service -> product -> CVE)

This is a minimal regex-based implementation. Supporting more flexible natural-language
questions in production (different phrasings, combined conditions, etc.) would mean
using an LLM for the part that extracts intent (CVE ID / service name / severity filter,
etc.) from the question text, then calling the same graph-query functions underneath.
This prototype uses regex instead, since no ANTHROPIC_API_KEY (or similar) was
available in this environment.

Usage: python scripts/ask.py "Which service does CVE-2024-34351 affect?"
       python scripts/ask.py "Which CVEs affect web-frontend?"
"""
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def load():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]
    product_to_services = defaultdict(list)
    cve_to_products = defaultdict(list)
    service_to_products = defaultdict(list)
    for s, t, kind in edges:
        if kind == "depends_on":
            product_to_services[t].append(s)
            service_to_products[s].append(t)
        elif kind == "affects":
            cve_to_products[s].append(t)
    return nodes, product_to_services, cve_to_products, service_to_products


def answer_cve_to_services(cve_id, nodes, product_to_services, cve_to_products):
    if cve_id not in nodes:
        return f"{cve_id} was not found in the graph."
    products = cve_to_products.get(cve_id, [])
    affected = {}
    for p in products:
        for svc in product_to_services.get(p, []):
            affected.setdefault(svc, []).append(p)
    sev = nodes[cve_id].get("severity")
    if not affected:
        return f"{cve_id} (severity: {sev}) does not affect any registered service."
    lines = [f"{cve_id} (severity: {sev}) affects the following services:"]
    for svc, via in affected.items():
        lines.append(f"  - {nodes[svc]['label']} (via: {', '.join(nodes[p]['label'] for p in via)})")
    return "\n".join(lines)


def answer_service_to_cves(service_name, nodes, service_to_products, cve_to_products):
    svc_key = f"svc:{service_name}"
    if svc_key not in nodes:
        known = [v["label"] for k, v in nodes.items() if v["type"] == "Service"]
        return f"Service \"{service_name}\" not found. Registered services: {known}"
    products = set(service_to_products.get(svc_key, []))
    hits = [cid for cid, prods in cve_to_products.items() if set(prods) & products]
    if not hits:
        return f"No CVEs are registered as affecting {service_name}."
    lines = [f"CVEs affecting {service_name} ({len(hits)}):"]
    for cid in sorted(hits):
        lines.append(f"  - {cid} (severity: {nodes[cid].get('severity')})")
    return "\n".join(lines)


def main():
    question = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Which service does CVE-2024-34351 affect?"
    nodes, p2s, c2p, s2p = load()

    m = CVE_PATTERN.search(question)
    if m:
        print(answer_cve_to_services(m.group(0).upper(), nodes, p2s, c2p))
        return

    services = [v["label"] for k, v in nodes.items() if v["type"] == "Service"]
    for svc in services:
        if svc in question:
            print(answer_service_to_cves(svc, nodes, s2p, c2p))
            return

    print("Could not recognize the intent of the question (include a CVE ID or a service name).")
    print("Registered services:", services)


if __name__ == "__main__":
    main()
