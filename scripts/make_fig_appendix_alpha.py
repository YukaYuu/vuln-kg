"""Appendix: apply the author's other research (alpha-mixed bipartite-graph layout,
the "bipartite-layout" project) to the CVE x Product bipartite graph here.

U = CVE (90 nodes), M = Product (49 nodes), real edges = the CVE-Product "affects"
relation. CVE nodes are colored by which fictional service they affect
(none / web-frontend / api-gateway / ...).

This is not the main visualization method of this project (the GxP technology survey);
it's an example of applying a separate piece of research -- a bipartite graph layout
method that mixes real edges with "virtual" edges (based on neighbor overlap between
same-type nodes) via a continuous parameter alpha -- to this CVE dataset.

Requires the sibling "bipartite-layout" repository to be available locally (see
BIPARTITE_LAYOUT_SRC below); it is a separate project and not vendored into this one.

Usage: python scripts/make_fig_appendix_alpha.py
Output: figures/fig_appendix_alpha.png
"""
import json
import os
import sys
from pathlib import Path

# Path to the sibling bipartite-layout repo's `src` directory. Override with the
# BIPARTITE_LAYOUT_SRC environment variable if it isn't checked out next to this repo.
BIPARTITE_LAYOUT_SRC = os.environ.get(
    "BIPARTITE_LAYOUT_SRC",
    str(Path(__file__).resolve().parent.parent.parent / "bipartite-layout" / "src"),
)
sys.path.insert(0, BIPARTITE_LAYOUT_SRC)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.collections import LineCollection
import networkx as nx

from bipartite_layout.matrices import build_matrices
from bipartite_layout.linlog import compute_koala_alpha_layout

plt.rcParams["font.family"] = ["Arial", "DejaVu Sans"]

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
FIGURES = HERE.parent / "figures"

SERVICE_COLORS = {
    "none": "#cccccc",
    "web-frontend": "#0072B2",
    "api-gateway": "#D55E00",
    "legacy-admin-panel": "#009E73",
    "webmail": "#CC79A7",
    "data-pipeline": "#E69F00",
}


def main():
    g = json.loads((DATA / "company_graph.json").read_text(encoding="utf-8"))
    nodes, edges = g["nodes"], g["edges"]

    # CVE -> affected service (first one if there are several, "none" if there are none)
    cve_to_products = {}
    product_to_services = {}
    for s, t, kind in edges:
        if kind == "affects":
            cve_to_products.setdefault(s, []).append(t)
        elif kind == "depends_on":
            product_to_services.setdefault(t, []).append(nodes[s]["label"])
    cve_service = {}
    for cid, prods in cve_to_products.items():
        svcs = [svc for p in prods for svc in product_to_services.get(p, [])]
        cve_service[cid] = svcs[0] if svcs else "none"

    G = nx.Graph()
    for s, t, kind in edges:
        if kind == "affects":
            G.add_edge(f"u_{s}", f"m_{t}")

    node_list, node_idx, common_deg, weight, is_user = build_matrices(G, threshold_common_deg=None, top_k_same_type=6)
    print(f"N={len(node_list)} (CVE={sum(is_user)}, Product={sum(~is_user)}), edges={G.number_of_edges()}")

    cve_idx = np.where(is_user)[0]
    product_idx = np.where(~is_user)[0]
    cve_colors = [SERVICE_COLORS[cve_service.get(node_list[i][2:], "none")] for i in cve_idx]

    alphas = [0.0, 0.3, 0.6, 1.0]
    x0 = None
    fig, axes = plt.subplots(1, len(alphas), figsize=(5.2 * len(alphas), 5.2))
    for ax, a in zip(axes, alphas):
        coords, energy, converged, nit, gnorm = compute_koala_alpha_layout(
            common_deg, weight, a, seed=0, maxiter=2000,
            real_weight_mode="epsilon_floor", real_edge_epsilon=0.1,
            crossover_exponent=1.0, grav_factor=0.05,
            mesh_init=(x0 is None), x0=x0,
        )
        x0 = coords.flatten()
        print(f"  alpha={a:.1f} converged={converged}")

        edges_idx = np.array([[node_idx[u], node_idx[v]] for u, v in G.edges()])
        segs = coords[edges_idx]
        ax.add_collection(LineCollection(segs, colors="#333333", linewidths=0.3, alpha=0.4, zorder=1))
        ax.scatter(*coords[product_idx].T, s=14, c="#444444", marker="s", alpha=0.6, zorder=2, label="Product")
        ax.scatter(*coords[cve_idx].T, s=22, c=cve_colors, marker="o", edgecolors="white", linewidths=0.3, zorder=3)
        ax.set_xticks([]); ax.set_yticks([])
        ax.set_aspect("equal", adjustable="box")
        for sp in ax.spines.values():
            sp.set_color("#bbbbbb"); sp.set_linewidth(0.5)
        ax.set_title(rf"$\alpha$ = {a:.1f}", fontsize=13)

    handles = [plt.Line2D([], [], marker="o", ls="", color=c, ms=9, label=svc) for svc, c in SERVICE_COLORS.items()]
    handles.append(plt.Line2D([], [], marker="s", ls="", color="#444444", ms=8, label="Product"))
    fig.legend(handles=handles, loc="lower center", ncol=6, fontsize=9, frameon=False, bbox_to_anchor=(0.5, -0.05))
    fig.suptitle("Appendix: applying alpha-mixed bipartite layout (separate research) to CVE x Product data", fontsize=13)
    fig.subplots_adjust(bottom=0.12, top=0.88, wspace=0.05)
    out = FIGURES / "fig_appendix_alpha.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print("saved:", out)


if __name__ == "__main__":
    main()
