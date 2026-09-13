# Architecture layout

## Inspection and responsibilities

The scanner renders Helm with `helm template`, extracts Kubernetes resource
objects, and persists them through `normalize-service-overview.py` as
`rendered_resources`. The portal does not parse Helm templates or assign
coordinates while reading manifests.

`architecture.py` accepts the supported resource collections from an assessment
payload and its service overview. It normalizes resource identity as
kind/namespace/name and discovers relationships using namespace-scoped Service
selectors, Ingress backends, workload image/configuration/storage references,
NetworkPolicy evidence, and conservative exact environment references. Resolved
Ingresses receive a local synthetic external endpoint. Nodes carry their kind,
name, namespace, evidence, display label and available ports. Edges carry stable
identity, direction, classification, evidence, confidence and port mappings.

The existing supported kinds and inference rules remain the semantic boundary;
this is not a general Kubernetes CRD dependency analyzer. In particular, Gateway
and Route discovery, nested claim templates and some workload reference forms
are not added by this layout refactor.

`architecture_layout.py` is a custom Python geometry engine, without a third-party
graph library. View projections select resource kinds and relationships; Data
Flow combines equivalent communications while retaining their supporting
evidence. Declared, derived and inferred relationships share geometry rules.
The Data Flow projection now also retains discovered connections without port
metadata (for example, a selector relationship labeled `selects`).

Before this refactor, weak connected components were already discovered, but
their positions were unconditionally stacked vertically. Label widths grew
without wrapping. The browser used a fixed 1200 × 620 viewBox, fixed fit
calculations and a minimum SVG width, with no resize reflow. The parser also
maintained a second rank calculation, and relationship IDs depended on discovery
order. There were no product-name positioning rules in the architecture path.

The legacy Helm export was a separate chart/image provenance summary using
global columns. When rendered Kubernetes resources exist, that compatibility
URL now calls the canonical architecture export. Assessments containing only
old chart/image/port summaries retain their provenance summary so that evidence
is not lost or converted into invented Kubernetes topology.

## Geometry pipeline

1. Sort canonical resources and relationships deterministically. Relationship
   IDs are hashes of their semantic identity rather than counters.
2. Project the requested view and discover weak connected components with an
   adjacency traversal. A shared dependency keeps its entire topology together.
3. Rank each component by directed relationships, independently of other groups.
   Thus external → Ingress → Service → workload naturally runs left to right,
   while a downstream Service follows the workload that calls it. No empty
   semantic layers or global kind columns are inserted. Stable cycle entry
   selection uses semantic identity; feedback edges remain in the graph.
4. Apply deterministic neighbor-order sweeps inside ranks to reduce crossings.
   Use fixed 184 × 56 node boxes and label-aware rank/row spacing.
5. Allocate distinct boundary anchors and choose short routes with penalties for
   node intersections and shared segments. Place wrapped labels away from nodes,
   arrowheads and existing labels. If crowded convergence leaves no readable
   position, reserve an exterior route/label track inside the same component.
6. Measure each component including nodes, routes, labels and margins. Cache
   this viewport-independent geometry in a bounded 256-entry LRU.
7. Pack component rectangles along a bottom-left skyline for the available
   canvas width. Tall groups go first, with stable dimension/identity tie breaks.
   Small groups can stack in free space beside tall groups. Group margins supply
   horizontal and vertical gutters; no fixed number of columns is used.
8. Translate all geometry together. Routing and labels are computed locally
   before packing specifically so packing can account for their real bounds;
   translation preserves those routes exactly and avoids rerouting on resize.

Routing and ordering are heuristics, not a crossing-free guarantee for arbitrary
nonplanar graphs. Very dense topologies may need exterior tracks and therefore
larger bounds. Oversized connected components remain intact and can require
panning. Packing cannot eliminate their intrinsic width.

## Browser and exports

`architecture_graph.js` renders the supplied geometry using the existing CATS
classes, colors and classification styles. Labels use multiple SVG tspans;
long resource names use bounded display text with a full-name tooltip and
selection details. `architecture_export.py` follows the same geometry and text
rules for SVG downloads.

The browser observes its actual SVG dimensions, updates the viewBox to CSS pixel
dimensions, and requests layouts from the existing authorized service page with
`architecture=true&layout_width=...`. Widths are quantized to 16 pixels, changes
are debounced for 180 ms, and obsolete requests are aborted and ignored. The
endpoint validates widths and reuses the page's service-view authorization.
Normalization/projection still runs for a resize request, while expensive local
routing is cached; no layout request occurs on ordinary selection redraws.

Initial view and Fit use 100% size, center graphs that fit, and align oversized
graphs to their beginning. Existing zoom and drag-to-pan controls remain. The
canvas no longer reserves an empty details column or forces a 720-pixel minimum
SVG width. A large graph can extend beyond the visible canvas and be panned.

## Validation and fixtures

Run from `portal`:

```text
../.venv/Scripts/python.exe -m pytest tests -q
node --check app/static/architecture_graph.js
```

The original architecture tests cover normalization, classification, topology,
external endpoints, anchored routes, labels, view projections, exports and the
scanner-to-portal handoff. `test_architecture_packing.py` adds pairs and fan-in
across Deployment/StatefulSet/DaemonSet, eight-flow reflow at 1000/1400/1920 usable
pixels, mixed-size packing, cache reuse, long port lists, shuffled source order,
cycles, portless selectors and dense many-to-many labels. The portal endpoint
test checks width validation, authorization, reflow and canonical legacy export.

`tests/fixtures-helm-demo-rendered.yaml` was generated from the existing
`scanning-main/examples/helm-diagram-demo` chart using Helm 3.17.3:

```text
helm template demo scanning-main/examples/helm-diagram-demo
```

The fixture regression covers its Deployments, StatefulSets, Services, Ingress,
configuration resources and external entry point, including reversed document
order. The repository's named Loki/Flux/Vector/application examples were not
found as rendered fixtures; generic synthetic shapes are not claimed as tests
of those actual charts.

Browser inspection used an isolated in-memory test instance at wide and narrow
viewport sizes to confirm component reflow, 100% text, arrowheads and CATS styling.

Final validation: **161 portal tests passed**. JavaScript syntax and Python
compilation checks passed. A local timing check of 100 independent flows took
approximately 48 ms to build six initial views and 5 ms to repack the cached
Data Flow view; these are development-machine measurements, not an SLA.

## Changed files

| File (relative to `portal`) | Change |
| --- | --- |
| `app/architecture.py` | Stable resource/relationship identity; reuse layout ranking; accept canvas width |
| `app/architecture_layout.py` | Cached component geometry, skyline packing, wrapped labels, dense-label tracks, cycle handling |
| `app/architecture_export.py` | Multiline labels and bounded names in canonical SVG export |
| `app/helm_diagram.py` | Send resource-backed legacy exports through canonical geometry/rendering |
| `app/main.py` | Authorized width-aware layout response on the existing service page |
| `app/static/architecture_graph.js` | Debounced resize, actual canvas coordinates, readable initial view, multiline labels and name tooltips |
| `app/static/app.css` | Allow canvas width to respond and reclaim hidden details-panel space |
| `tests/test_architecture_packing.py` | Generic topology, packing, cache, determinism, labels and Helm fixture regressions |
| `tests/test_portal.py` | Resize endpoint, authorization, input validation and compatibility export test |
| `tests/fixtures-helm-demo-rendered.yaml` | Actual rendered repository Helm demo fixture |
| `docs/architecture-layout.md` | Inspection, design, validation and limitations |
