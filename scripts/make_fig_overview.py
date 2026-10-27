"""Build the overall CVE-CWE-Product-Service graph figure (for the written report).

Color-coded by node type: CVE (gray), CWE (orange), Product (blue), Service (green, larger).
Uses a force-directed layout (networkx spring_layout) so that even with many nodes,
the structure (Products and CVEs hanging off each Service) stays legible.

Usage: python scripts/make_fig_overview.py
Output: figures/fig_overview.png
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

plt.rcParams["font.family"] = ["Arial", "DejaVu Sans"]

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
FIGURES = HERE.parent / "figures"

COLOR = {"CVE": "#9aa3b0", "CWE": "#E69F00", "Product": "#0072B2", "Service": "#2ca02c"}
SIZE = {"CVE": 18, "CWE": 40, "Product": 50, "Service": 220}


def main():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]

    G = nx.Graph()
    for nid, n in nodes.items():
        G.add_node(nid, type=n["type"])
    for s, t, kind in edges:
        G.add_edge(s, t, kind=kind)

    pos = nx.spring_layout(G, k=0.25, seed=0, iterations=200)

    fig, ax = plt.subplots(figsize=(14, 10))
    for ntype, color in COLOR.items():
        xs = [pos[n][0] for n in G if G.nodes[n]["type"] == ntype]
        ys = [pos[n][1] for n in G if G.nodes[n]["type"] == ntype]
        ax.scatter(xs, ys, c=color, s=SIZE[ntype], label=ntype, zorder=3,
                   edgecolors="white" if ntype == "Service" else "none", linewidths=1.2)

    for s, t in G.edges():
        x1, y1 = pos[s]
        x2, y2 = pos[t]
        ax.plot([x1, x2], [y1, y2], color="#cccccc", linewidth=0.4, zorder=1)

    # Only label Service nodes (labeling the rest would be far too cluttered).
    for n in G:
        if G.nodes[n]["type"] == "Service":
            x, y = pos[n]
            ax.annotate(nodes[n]["label"], (x, y), fontsize=11, fontweight="bold",
                        xytext=(6, 6), textcoords="offset points")

    ax.set_xticks([]); ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.legend(loc="upper right", fontsize=11, frameon=False)
    ax.set_title("CVE - CWE - Product - Service graph (90 CVEs, 5 fictional services)", fontsize=13)
    fig.tight_layout()
    out = FIGURES / "fig_overview.png"
    fig.savefig(out, dpi=150)
    print("saved:", out)


if __name__ == "__main__":
    main()
