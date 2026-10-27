"""Answer "which of our services does this CVE affect?" by walking the graph.

A minimal implementation that just follows the path
CVE -> (affects) -> Product -> (reverse of depends_on) -> Service.
A natural-language question-answering layer on top of this (GraphRAG-style) would be
the next stage, built on top of this same graph traversal.

Usage: python scripts/query_impact.py CVE-2020-5284
       python scripts/query_impact.py --all   # list affected services for all 90 CVEs
"""
import json
import sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"


def load():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]
    # product -> services (reverse lookup of depends_on)
    product_to_services = defaultdict(list)
    cve_to_products = defaultdict(list)
    for s, t, kind in edges:
        if kind == "depends_on":
            product_to_services[t].append(s)
        elif kind == "affects":
            cve_to_products[s].append(t)
    return nodes, product_to_services, cve_to_products


def impact(cve_id, nodes, product_to_services, cve_to_products):
    if cve_id not in nodes or nodes[cve_id]["type"] != "CVE":
        return None
    products = cve_to_products.get(cve_id, [])
    affected = {}
    for p in products:
        for svc_key in product_to_services.get(p, []):
            affected.setdefault(svc_key, []).append(p)
    return {
        "cve": cve_id,
        "severity": nodes[cve_id].get("severity"),
        "score": nodes[cve_id].get("score"),
        "products": products,
        "affected_services": affected,  # svc_key -> [products it's affected through]
    }


def main():
    nodes, p2s, c2p = load()

    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        cve_ids = [n for n, v in nodes.items() if v["type"] == "CVE"]
        hit = 0
        for cid in sorted(cve_ids):
            r = impact(cid, nodes, p2s, c2p)
            if r["affected_services"]:
                hit += 1
                svcs = ", ".join(nodes[k]["label"] for k in r["affected_services"])
                print(f"{cid} [{r['severity']}]  -> {svcs}")
        print(f"\nFlagged as affecting a service: {hit} / {len(cve_ids)}")
        return

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2020-5284"
    r = impact(cve_id, nodes, p2s, c2p)
    if r is None:
        print(f"{cve_id}: not found in the graph")
        return
    print(f"CVE: {r['cve']}  severity: {r['severity']} (score={r['score']})")
    print(f"Affected product(s): {', '.join(nodes[p]['label'] for p in r['products'])}")
    if r["affected_services"]:
        print("Affected service(s):")
        for svc_key, via_products in r["affected_services"].items():
            via = ", ".join(nodes[p]["label"] for p in via_products)
            print(f"  - {nodes[svc_key]['label']} (via: {via})")
    else:
        print("Affected service(s): none")


if __name__ == "__main__":
    main()
