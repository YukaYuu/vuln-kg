"""Convert CVE data fetched from the NVD (data/raw_*.json) into a CVE-CWE-CPE graph.

Nodes: CVE (vulnerability), CWE (weakness type), CPE (affected product/version range)
Edges: CVE-CWE (this vulnerability is this type of weakness),
       CVE-CPE (this vulnerability affects this product)

CPE is turned into a node at the vendor:product granularity rather than the full
version string (e.g. nodejs:node.js), with the version range kept as an edge
attribute instead.

Usage: python scripts/build_graph.py
Output: data/graph.json
"""
import json
import glob
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"


def cpe_product_key(criteria):
    # cpe:2.3:a:vendor:product:version:... -> "vendor:product"
    parts = criteria.split(":")
    if len(parts) < 5:
        return None
    return f"{parts[3]}:{parts[4]}"


def load_cves():
    cves = {}
    for f in glob.glob(str(DATA / "raw_*.json")):
        d = json.load(open(f, encoding="utf-8"))
        for v in d.get("vulnerabilities", []):
            c = v["cve"]
            cves[c["id"]] = c  # dedup across keyword searches
    return cves


def main():
    cves = load_cves()
    print(f"CVE count (after dedup): {len(cves)}")

    nodes = {}  # id -> {type, label, ...}
    edges = []  # (src, dst, kind)

    for cid, c in cves.items():
        desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
        metrics = c.get("metrics", {})
        severity, score = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss = metrics[key][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
                break
        nodes[cid] = {"type": "CVE", "label": cid, "desc": desc, "severity": severity, "score": score}

        for w in c.get("weaknesses", []):
            for d in w["description"]:
                if d["lang"] == "en" and d["value"].startswith("CWE-"):
                    cwe_id = d["value"]
                    nodes.setdefault(cwe_id, {"type": "CWE", "label": cwe_id})
                    edges.append((cid, cwe_id, "has_weakness"))

        seen_products = set()
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    key = cpe_product_key(m.get("criteria", ""))
                    if not key or key in seen_products:
                        continue
                    seen_products.add(key)
                    nodes.setdefault(key, {"type": "Product", "label": key})
                    edges.append((cid, key, "affects"))

    print(f"Node count: {len(nodes)} (breakdown: "
          f"CVE={sum(1 for n in nodes.values() if n['type']=='CVE')}, "
          f"CWE={sum(1 for n in nodes.values() if n['type']=='CWE')}, "
          f"Product={sum(1 for n in nodes.values() if n['type']=='Product')})")
    print(f"Edge count: {len(edges)}")

    out = {"nodes": nodes, "edges": edges}
    out_path = DATA / "graph.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
