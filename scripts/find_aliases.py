"""Detect CPE identifier inconsistencies algorithmically, instead of by hand.

While investigating a recall gap in evaluate_search.py, manually diffing the missed
CVEs' CPE strings turned up 3 cases where NextAuth.js was registered with its
vendor/product fields swapped. That was a single, manually-found instance -- nobody had
checked whether the same kind of inconsistency was still lurking elsewhere.

This script mechanically applies two kinds of normalization across all 49 Product node
keys (in "vendor:product" form) and enumerates every candidate inconsistency.

1. Vendor/product field swap detection:
   normalize the two tokens of "vendor:product" and turn them into a frozenset.
   next-auth:nextauth.js and nextauth.js:next-auth both become
   frozenset({"next-auth", "nextauth.js"}), so they land in the same group.

2. Product-name variant detection (candidates for the same underlying software, under
   a different vendor or spelling):
   normalize only the product side to alphanumeric characters ("node.js" -> "nodejs").
   nodejs:node.js, joyent:node.js, and nodejs:nodejs all normalize to "nodejs" and land
   in the same group (joyent is Node.js's vendor name from before it was transferred to
   the Node.js Foundation in 2015).

Usage: python scripts/find_aliases.py
"""
import json
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"


def normalize_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def product_keys():
    g = json.loads((DATA / "graph.json").read_text(encoding="utf-8"))
    return [k for k, v in g["nodes"].items() if v["type"] == "Product"]


def find_vendor_product_swaps(keys):
    groups = defaultdict(list)
    for k in keys:
        vendor, product = k.split(":", 1)
        fp = frozenset({normalize_token(vendor), normalize_token(product)})
        groups[fp].append(k)
    return {fp: ks for fp, ks in groups.items() if len(ks) > 1}


def find_product_name_variants(keys):
    groups = defaultdict(list)
    for k in keys:
        _, product = k.split(":", 1)
        groups[normalize_token(product)].append(k)
    return {norm: ks for norm, ks in groups.items() if len(ks) > 1}


def main():
    keys = product_keys()
    print(f"Total Product nodes: {len(keys)}")

    print("\n--- 1. Candidate vendor/product field swaps ---")
    swaps = find_vendor_product_swaps(keys)
    if not swaps:
        print("None found")
    for fp, ks in swaps.items():
        print(f"  {sorted(fp)}: {ks}")

    print("\n--- 2. Candidate product-name variants (possible same software) ---")
    variants = find_product_name_variants(keys)
    if not variants:
        print("None found")
    for norm, ks in variants.items():
        print(f"  normalized='{norm}': {ks}")

    total_candidates = sum(len(ks) for ks in swaps.values()) + sum(len(ks) for ks in variants.values())
    print(f"\nDoes the known manually-found case (NextAuth.js, next-auth<->nextauth.js) show up "
          f"in the swap detector? "
          f"{'next-auth:nextauth.js' in [k for ks in swaps.values() for k in ks]}")
    print(f"Total candidate Product keys flagged (with overlap): {total_candidates} / {len(keys)}")


if __name__ == "__main__":
    main()
