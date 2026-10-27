"""Connect a fictional SaaS company's ("Acme SaaS") service architecture to the CVE
graph (data/graph.json).

No real company's data is used anywhere in this project. This is a toy setup
(a research example) modeling a generic "SaaS that runs on Node.js/PHP/Next.js."
Only the actual products each service depends on (the Product nodes) come from real
data (NVD's CPE identifiers).

Nodes: Service (a fictional service)
Edges: depends_on (Service -> Product)

Usage: python scripts/build_company_graph.py
Output: data/company_graph.json (data/graph.json's nodes/edges, plus Service nodes
        and depends_on edges)
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
sys.path.insert(0, str(HERE))
from schema import validate_edge, validate_graph, EdgeConstraintViolation  # noqa: E402

# service name -> products it depends on (must match Product node keys in graph.json)
SERVICES = {
    # next-auth:nextauth.js and nextauth.js:next-auth are the same NextAuth.js
    # package, but registered with vendor/product swapped between NVD records
    # (see the identifier-inconsistency finding in find_aliases.py).
    # apollographql:apollo_client and idopesok:zsa are the CPEs of the general-purpose
    # libraries that Next.js-specific wrapper packages (@apollo/...-nextjs, zsa) depend
    # on; a vulnerability in the wrapper itself is sometimes registered under these CPEs.
    "web-frontend": [
        "vercel:next.js", "zeit:next.js",
        "next-auth:nextauth.js", "nextauth.js:next-auth",
        "auth0:nextjs-auth0",
        "apollographql:apollo_client", "idopesok:zsa",
    ],
    "api-gateway": ["nodejs:node.js", "joyent:node.js", "npmjs:npm"],
    "legacy-admin-panel": ["php:php", "phpmyadmin:phpmyadmin"],
    "webmail": ["squirrelmail:squirrelmail", "php:php"],
    "data-pipeline": ["sequelize_project:sequelize", "nodejs:node.js"],
}


def main():
    g = json.loads((DATA / "graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]

    missing = []
    for svc, products in SERVICES.items():
        svc_key = f"svc:{svc}"
        nodes[svc_key] = {"type": "Service", "label": svc}
        for p in products:
            if p not in nodes:
                missing.append(p)
                continue
            # Edge-constraint check: any combination other than
            # Service --depends_on--> Product is rejected. Same idea as a real
            # knowledge-graph REST API rejecting edge creation outside its declared
            # edge constraints -- expressed here as a runtime Python exception.
            validate_edge("Service", "depends_on", "Product")
            edges.append((svc_key, p, "depends_on"))

    if missing:
        print("Warning: product keys not found in graph.json (skipped):", missing)

    # Validate the whole graph end-to-end, including the CVE-CWE/CVE-Product edges
    # that came from build_graph.py.
    ok, violations = validate_graph(nodes, edges)
    print(f"Edge constraint check: {ok}/{len(edges)} edges valid ({len(violations)} violations)")
    if violations:
        raise EdgeConstraintViolation(f"Found {len(violations)} disallowed edge(s): {violations[:3]}")

    print(f"Services: {len(SERVICES)}")
    print(f"Total nodes: {len(nodes)}")
    print(f"Total edges: {len(edges)}")

    out = {"nodes": nodes, "edges": edges}
    out_path = DATA / "company_graph.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
