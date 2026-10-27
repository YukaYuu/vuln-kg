"""Declare and validate the graph schema (node type / predicate / edge constraint).

Until now, build_graph.py / build_company_graph.py created nodes and edges with
no constraints at all -- anything could connect to anything. Real-world knowledge-graph
platforms typically enforce an explicit three-layer schema (node type / predicate /
edge constraint): a given predicate is only valid between specific node types, and any
other combination is rejected outright.

This module applies the same idea to this project's own graph:
  - NODE_TYPES: the node types allowed in this graph.
  - EDGE_CONSTRAINTS: the allow-list of (subject_type, predicate, object_type) triples.
  - validate_edge(): checks whether a given edge satisfies the constraints and raises
                     an exception if it doesn't (the same idea as a real knowledge-graph
                     API returning an explicit error such as
                     "Cannot create a writable edge between two system nodes").

Usage: python scripts/schema.py  (validates every edge in company_graph.json)
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"

NODE_TYPES = {"CVE", "CWE", "Product", "Service"}

# Allow-list of (subject_type, predicate, object_type) triples.
EDGE_CONSTRAINTS = {
    ("CVE", "has_weakness", "CWE"),
    ("CVE", "affects", "Product"),
    ("Service", "depends_on", "Product"),
}


class EdgeConstraintViolation(Exception):
    pass


def validate_edge(subject_type, predicate, object_type):
    if subject_type not in NODE_TYPES:
        raise EdgeConstraintViolation(f"Unknown node type: {subject_type}")
    if object_type not in NODE_TYPES:
        raise EdgeConstraintViolation(f"Unknown node type: {object_type}")
    if (subject_type, predicate, object_type) not in EDGE_CONSTRAINTS:
        raise EdgeConstraintViolation(
            f"Edge constraint violation: {subject_type} --{predicate}--> {object_type} is not allowed. "
            f"Allowed: {sorted(EDGE_CONSTRAINTS)}"
        )


def validate_graph(nodes, edges):
    ok, violations = 0, []
    for s, t, kind in edges:
        s_type = nodes[s]["type"]
        t_type = nodes[t]["type"]
        try:
            validate_edge(s_type, kind, t_type)
            ok += 1
        except EdgeConstraintViolation as e:
            violations.append((s, kind, t, str(e)))
    return ok, violations


def main():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]
    ok, violations = validate_graph(nodes, edges)
    print(f"Validated edges: {ok} / {len(edges)}")
    if violations:
        print(f"Violations: {len(violations)}")
        for v in violations[:10]:
            print(" ", v)
    else:
        print("No edge constraint violations.")

    # As a worked example of a rejection, try an intentionally invalid edge
    # (a direct Product-to-Product connection).
    print("\n--- Trying an intentionally invalid edge ---")
    try:
        validate_edge("Product", "affects", "Product")
    except EdgeConstraintViolation as e:
        print("Rejected as expected:", e)


if __name__ == "__main__":
    main()
