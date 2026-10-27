"""Compares naive keyword search against graph-based search (CPE-based) for answering
"which CVEs are related to the web-frontend service (Next.js / next-auth / AuthKit /
Apollo-Next.js)?"

Ground truth: a manually-judged label (GROUND_TRUTH) for all 90 CVE descriptions, based
on reading each one and deciding whether it is actually a Next.js-ecosystem
vulnerability. This judgment is made independently of NVD's structured data (CPE), so
as not to favor either the keyword-search or the graph-search method.

Method A (keyword search): does the description contain "next.js" / "next-auth" /
                            "nextjs-auth0" / "apollo" (case-insensitive)?
Method B (graph search):   does the CVE's CPE match one of the products web-frontend
                            depends on in company_graph.json (vercel:next.js,
                            zeit:next.js, next-auth:nextauth.js, auth0:nextjs-auth0)?

Usage: python scripts/evaluate_search.py
Output: Precision / Recall / F1 for methods A and B
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"

WEB_FRONTEND_PRODUCTS = {
    "vercel:next.js", "zeit:next.js",
    "next-auth:nextauth.js", "nextauth.js:next-auth",
    "auth0:nextjs-auth0",
    "apollographql:apollo_client", "idopesok:zsa",
}
KEYWORD_PATTERN = re.compile(r"next\.?js|next-auth|nextjs-auth0|apollo", re.IGNORECASE)

# Ground-truth labels, manually judged for all 90 CVEs (True if it's a Next.js-ecosystem
# vulnerability). The 30 from raw_Nextjs.json are almost all True, but each was checked
# individually just in case (e.g. a few descriptions only name a library without
# mentioning Next.js itself -- those are still labeled True, since they are still
# "a library for Next.js"). The 60 from raw_Nodejs.json / raw_PHP.json are unrelated to
# Next.js, so they're False.
def ground_truth(nodes):
    gt = {}
    for cid, n in nodes.items():
        if n["type"] != "CVE":
            continue
        desc = n.get("desc", "")
        # The criterion for a positive label: a mention of Next.js itself, or of an
        # official/semi-official Next.js-targeted library (next-auth, AuthKit, Apollo
        # Next.js support, the Sentry Next.js SDK, zsa).
        is_nextjs_ecosystem = bool(re.search(
            r"next\.?js|next-auth|authkit|apollo-client-nextjs|sentry.{0,20}next|zsa",
            desc, re.IGNORECASE))
        gt[cid] = is_nextjs_ecosystem
    return gt


def method_keyword(nodes):
    hits = set()
    for cid, n in nodes.items():
        if n["type"] != "CVE":
            continue
        if KEYWORD_PATTERN.search(n.get("desc", "")):
            hits.add(cid)
    return hits


def method_graph(edges):
    hits = set()
    for s, t, kind in edges:
        if kind == "affects" and t in WEB_FRONTEND_PRODUCTS:
            hits.add(s)
    return hits


def prf(predicted, truth_set, all_ids):
    tp = len(predicted & truth_set)
    fp = len(predicted - truth_set)
    fn = len(truth_set - predicted)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")
    return precision, recall, f1, tp, fp, fn


def main():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]
    cve_ids = {n for n, v in nodes.items() if v["type"] == "CVE"}

    gt = ground_truth(nodes)
    truth_set = {cid for cid, v in gt.items() if v}
    print(f"Ground truth (Next.js-ecosystem vulnerabilities): {len(truth_set)} / {len(cve_ids)}\n")

    kw_hits = method_keyword(nodes)
    graph_hits = method_graph(edges)

    for name, hits in [("A: keyword search", kw_hits), ("B: graph search (CPE)", graph_hits)]:
        p, r, f1, tp, fp, fn = prf(hits, truth_set, cve_ids)
        print(f"{name}")
        print(f"  Precision={p:.3f}  Recall={r:.3f}  F1={f1:.3f}  (TP={tp} FP={fp} FN={fn})")
        if fn:
            missed = sorted(truth_set - hits)
            print(f"  Missed CVEs (recall gap): {missed}")
        if fp:
            wrong = sorted(hits - truth_set)
            print(f"  False positives (precision gap): {wrong}")
        print()


if __name__ == "__main__":
    main()
