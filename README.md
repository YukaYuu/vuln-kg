# Vulnerability Knowledge Graph: Does Graph Search Actually Beat Keyword Search?

A small knowledge-graph prototype built on real NVD vulnerability data, exploring a
specific question: when you connect CVEs, their weaknesses (CWE), and the products
they affect (CPE) into a graph, and then layer a company's service architecture on
top, does *graph-based* search for "which CVEs affect service X" actually outperform
plain keyword search over the vulnerability descriptions?

The short answer turned out to be: **not by default** -- and the reason why is the
interesting part. This repo contains the full pipeline, the evaluation, and two
follow-up pieces of work the initial result motivated: an automated detector for the
identifier inconsistencies that caused it, and a transitive-dependency resolver that
finds a different class of blind spot neither method can see on its own.

No real company's data is used anywhere in this project. The "company" and its five
services (`web-frontend`, `api-gateway`, `legacy-admin-panel`, `webmail`,
`data-pipeline`) are a fictional stand-in for a generic SaaS running on Node.js, PHP,
and Next.js. Only the vulnerability data itself (CVE/CWE/CPE) is real, pulled from the
[NVD](https://nvd.nist.gov/) public API.

## The pipeline

```
data/raw_*.json           90 real CVEs fetched from the NVD API
      │
      ▼  build_graph.py
data/graph.json           CVE – CWE – Product graph (171 nodes, 170 edges)
      │
      ▼  build_company_graph.py  (validated against scripts/schema.py)
data/company_graph.json   + 5 fictional Service nodes, depends_on edges (176 nodes, 186 edges)
```

From there, several scripts query or analyze the graph:

| Script | What it does |
|---|---|
| `query_impact.py` | "Which service does this CVE affect?" -- a direct graph traversal |
| `ask.py` | A minimal regex-based natural-language front end over the same traversal |
| `transitive_impact.py` | Resolves multi-hop ("my dependency's dependency") impact via BFS |
| `evaluate_search.py` | Keyword search vs. graph search, head to head, against a hand-labeled ground truth |
| `find_aliases.py` | Automatically detects CPE identifier inconsistencies (vendor/product swaps, naming variants) |
| `extract_entities.py` | Structured entity extraction from CVE free text (component, attack vector, auth requirement) |
| `schema.py` | Declares and enforces the graph's node-type / predicate / edge-constraint schema |
| `make_fig_overview.py`, `make_fig_appendix_alpha.py` | Figure generation |

## The finding: graph search lost to keyword search

For "which CVEs are relevant to `web-frontend` (Next.js / next-auth / AuthKit /
Apollo-Next.js)?", a naive CPE-based graph traversal scored **Recall = 0.600** against
a plain keyword search's **Recall = 1.000** -- missing 12 of 30 true positives.

The cause wasn't missing data: all 12 missed CVEs had CPE entries. Diffing the actual
CPE strings found that **NextAuth.js is registered with its `vendor` and `product`
fields transposed** between different NVD records:

```
cpe:2.3:a:nextauth.js:next-auth:...   (3 CVE records)
cpe:2.3:a:next-auth:nextauth.js:...   (what the service's dependency list declared)
```

Same package, two different node identities as far as the graph is concerned.
Normalizing that one known swap brought recall to 0.933. The remaining 2 misses were a
different failure mode entirely -- third-party wrapper packages (a Sentry SDK, a
WorkOS library) registered under their own CPE, simply absent from the declared
dependency list.

**Takeaway:** graph search is only as good as the identifier consistency of the
underlying data; keyword search over human-written text is oddly robust against
exactly the kind of tagging inconsistency that trips up the structured approach.
Neither one strictly dominates.

## Going further: finding the *next* inconsistency algorithmically

The NextAuth.js swap above was found by manually diffing 12 CPE strings by hand --
which only tells you about *that* dataset, not whether the same problem exists
elsewhere. `find_aliases.py` generalizes this into an actual detector: it normalizes
and groups all 49 product identifiers two ways (vendor/product token-swap, and
product-name-only) and flags every group with more than one member.

Run against this dataset, it both re-finds the known NextAuth.js case (a sanity check)
*and* surfaces one that was never caught by hand: `nodejs:node.js`, `nodejs:nodejs`,
and `joyent:node.js` all normalize to the same thing (`joyent` is Node.js's vendor name
from before its 2015 move to the Node.js Foundation). The `api-gateway` service's
dependency list declared the first two but not `nodejs:nodejs` -- which turned out to
have 3 real CVEs registered under it, invisible to the existing graph query, each with
"Node.js" spelled out in plain English in its description.

## Going further still: transitive dependencies

Everything above only traverses a *direct* `Service -> Product` declaration (one hop).
`transitive_impact.py` adds a small package-dependency graph and resolves multi-hop
impact via BFS -- for example, that `web-frontend` depends on Next.js, which in turn
runs on Node.js.

```
service               direct-dep CVEs   + transitive CVEs   delta
web-frontend           28                39                  +11
api-gateway            15                15                  +0
```

11 of Node.js's 13 CVEs in this dataset are invisible to `web-frontend` if you only
declare a direct dependency on `vercel:next.js` -- and critically, **neither keyword
search nor the CPE-based graph search catches them either**: their descriptions don't
mention "Next.js" at all. The only way to find them is to encode the actual runtime
fact ("Next.js apps need Node.js") into the graph. This is a third category of blind
spot that neither baseline reaches on its own.

## Schema enforcement

`schema.py` declares an explicit node-type / predicate / edge-constraint schema (the
same three-layer idea used by real knowledge-graph platforms) and `build_company_graph.py`
validates every edge against it at construction time, rejecting anything outside the
declared `(subject_type, predicate, object_type)` allow-list.

## Running it

```bash
pip install -r requirements.txt
python scripts/build_graph.py
python scripts/build_company_graph.py
python scripts/schema.py
python scripts/evaluate_search.py
python scripts/find_aliases.py
python scripts/transitive_impact.py
python scripts/query_impact.py CVE-2020-5284
python scripts/ask.py "Which service does CVE-2024-34351 affect?"
```

`make_fig_appendix_alpha.py` additionally requires a sibling checkout of my other
research project,
[bipartite-layout](https://github.com/YukaYuu/bipartite-layout) (a graph-layout
method I developed separately); it's not vendored into this repo. Set
`BIPARTITE_LAYOUT_SRC` to point at its `src/` directory if it isn't checked out next to
this one.

## Limitations

- Small scale (90 CVEs, 24 LLM-style entity extractions, 49 products) -- not a benchmark.
- The evaluation's ground-truth labels were judged by one person reading each
  description; no cross-checking was done.
- Entity extraction (`extract_entities.py`) was done by manually reading each
  description against a fixed schema, not via a live LLM API call (no API key was
  available in this environment) -- the schema itself is written to be directly
  reusable with one.
- The natural-language front end (`ask.py`) is a regex stand-in, not a real parser.
- Service dependency lists are hand-declared, not derived from a real SBOM -- which is
  exactly the kind of gap the recall numbers above expose. A production version would
  need to generate and keep these current from something like a CycloneDX/SPDX SBOM.
- The alias detector normalizes by exact string match after cleanup; it won't catch
  typos or abbreviations (e.g. "k8s" vs. "kubernetes") without a fuzzier matching step.

## Data source

Vulnerability data from the [National Vulnerability Database](https://nvd.nist.gov/)
public API (`services.nvd.nist.gov/rest/json/cves/2.0`), a U.S. government resource.

## License

MIT -- see [LICENSE](LICENSE).
