"""Inspect the nx graphs produced by one PIDSMaker construction run.

Usage:
    python inspect_construction.py --dataset CADETS_E3 --hash <construction_hash> \
        [--artifacts /home/artifacts] [--dates 2018-04-06,2018-04-07] \
        [--viz-window 0] [--viz-max-nodes 300] [--out construction_graphs]

The hash is the folder name under artifacts/construction/<dataset>/construction/.
A unique prefix of it is enough.

Everything is written to <out>/<dataset>_<hash>/:
    summary.txt          human-readable overview (start here)
    windows.csv          one row per time-window graph: sizes, node types, time span
    nodes.csv            one row per distinct node: id, type, label (its value), degrees, windows
    edge_labels.csv      every edge label (event type) and its count
    edge_schema.csv      every (src node type, edge label, dst node type) combination
    edge_examples.csv    a few concrete edges per edge label, with readable endpoints
    viz_<window>.html    interactive pyvis view of one time window
"""

import argparse
import collections
import csv
import glob
import os
import sys
from datetime import datetime, timezone

import torch

NODE_COLORS = {"subject": "#e4572e", "file": "#29a19c", "netflow": "#f3a712"}
EXAMPLES_PER_LABEL = 5


# ----------------------------------------------------------------------------- helpers


def ns_to_str(ns):
    try:
        return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f UTC"
        )
    except (ValueError, OverflowError, OSError, TypeError):
        return str(ns)


def short(s, n=60):
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def find_run_dir(artifacts, dataset, run_hash):
    base = os.path.join(artifacts, "construction", dataset, "construction")
    matches = [d for d in glob.glob(os.path.join(base, run_hash + "*")) if os.path.isdir(d)]
    if not matches:
        available = sorted(os.path.basename(d) for d in glob.glob(os.path.join(base, "*")))
        sys.exit(
            f"No construction run matching '{run_hash}' in {base}\n"
            f"Available hashes: {available or 'none (check --artifacts and --dataset)'}"
        )
    if len(matches) > 1:
        sys.exit(f"Hash prefix '{run_hash}' is ambiguous: {[os.path.basename(m) for m in matches]}")
    return matches[0]


def list_graph_files(run_dir, dates):
    files = []
    for date_dir in sorted(glob.glob(os.path.join(run_dir, "nx", "graph_*"))):
        date = os.path.basename(date_dir).replace("graph_", "")
        if dates and date not in dates:
            continue
        for f in sorted(os.listdir(date_dir)):
            files.append((date, f, os.path.join(date_dir, f)))
    return files


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


# ----------------------------------------------------------------------------- statistics


def collect_stats(files):
    nodes = {}  # node_id -> dict
    windows = []
    edge_labels = collections.Counter()
    edge_schema = collections.Counter()
    edge_examples = collections.defaultdict(list)
    node_attr_keys = collections.Counter()
    edge_attr_keys = collections.Counter()
    y_values = collections.Counter()
    node_type_label_counts = collections.defaultdict(collections.Counter)
    t_min_all, t_max_all, total_edges = None, None, 0

    for i, (date, name, path) in enumerate(files):
        print(f"[{i + 1}/{len(files)}] {date}/{name}", flush=True)
        G = torch.load(path, weights_only=False)

        types_in_window = collections.Counter()
        for n, d in G.nodes(data=True):
            node_attr_keys.update(d.keys())
            ntype = d.get("node_type", "?")
            types_in_window[ntype] += 1
            info = nodes.get(n)
            if info is None:
                info = nodes[n] = {
                    "type": ntype,
                    "label": d.get("label", ""),
                    "windows": 0,
                    "in": 0,
                    "out": 0,
                }
                node_type_label_counts[ntype][d.get("label", "")] += 1
            info["windows"] += 1
            info["in"] += G.in_degree(n)
            info["out"] += G.out_degree(n)

        t_min, t_max = None, None
        for u, v, d in G.edges(data=True):
            edge_attr_keys.update(d.keys())
            lbl = d.get("label", "?")
            t = d.get("time")
            edge_labels[lbl] += 1
            y_values[d.get("y")] += 1
            su, sv = G.nodes[u].get("node_type", "?"), G.nodes[v].get("node_type", "?")
            edge_schema[(su, lbl, sv)] += 1
            if len(edge_examples[lbl]) < EXAMPLES_PER_LABEL:
                edge_examples[lbl].append(
                    (lbl, u, su, G.nodes[u].get("label", ""), v, sv, G.nodes[v].get("label", ""),
                     t, ns_to_str(t), d.get("event_uuid", ""))
                )
            if t is not None:
                t = int(t)
                t_min = t if t_min is None else min(t_min, t)
                t_max = t if t_max is None else max(t_max, t)

        total_edges += G.number_of_edges()
        if t_min is not None:
            t_min_all = t_min if t_min_all is None else min(t_min_all, t_min)
            t_max_all = t_max if t_max_all is None else max(t_max_all, t_max)

        windows.append({
            "date": date, "window": name, "path": path,
            "nodes": G.number_of_nodes(), "edges": G.number_of_edges(),
            "subject": types_in_window.get("subject", 0),
            "file": types_in_window.get("file", 0),
            "netflow": types_in_window.get("netflow", 0),
            "first_event": ns_to_str(t_min) if t_min else "",
            "last_event": ns_to_str(t_max) if t_max else "",
        })

    return {
        "nodes": nodes, "windows": windows, "edge_labels": edge_labels,
        "edge_schema": edge_schema, "edge_examples": edge_examples,
        "node_attr_keys": node_attr_keys, "edge_attr_keys": edge_attr_keys,
        "y_values": y_values, "node_type_label_counts": node_type_label_counts,
        "t_min": t_min_all, "t_max": t_max_all, "total_edges": total_edges,
    }


# ----------------------------------------------------------------------------- outputs


def write_outputs(s, out_dir, dataset, run_dir):
    write_csv(
        os.path.join(out_dir, "windows.csv"),
        ["index", "date", "window", "nodes", "edges", "subject", "file", "netflow",
         "first_event", "last_event"],
        [[i, w["date"], w["window"], w["nodes"], w["edges"], w["subject"], w["file"],
          w["netflow"], w["first_event"], w["last_event"]] for i, w in enumerate(s["windows"])],
    )
    write_csv(
        os.path.join(out_dir, "nodes.csv"),
        ["node_id", "node_type", "label", "num_windows", "total_in_degree", "total_out_degree"],
        sorted(
            ([n, d["type"], d["label"], d["windows"], d["in"], d["out"]]
             for n, d in s["nodes"].items()),
            key=lambda r: (r[1], -(r[4] + r[5])),
        ),
    )
    write_csv(
        os.path.join(out_dir, "edge_labels.csv"),
        ["edge_label", "count", "percent"],
        [[l, c, f"{100 * c / max(s['total_edges'], 1):.2f}"]
         for l, c in s["edge_labels"].most_common()],
    )
    write_csv(
        os.path.join(out_dir, "edge_schema.csv"),
        ["src_node_type", "edge_label", "dst_node_type", "count"],
        [[a, l, b, c] for (a, l, b), c in s["edge_schema"].most_common()],
    )
    write_csv(
        os.path.join(out_dir, "edge_examples.csv"),
        ["edge_label", "src_id", "src_type", "src_label", "dst_id", "dst_type", "dst_label",
         "time_ns", "time_utc", "event_uuid"],
        [row for lbl in sorted(s["edge_examples"]) for row in s["edge_examples"][lbl]],
    )

    # ---------------- summary.txt
    nodes = s["nodes"]
    type_counts = collections.Counter(d["type"] for d in nodes.values())
    L = []
    L.append(f"Dataset:           {dataset}")
    L.append(f"Construction run:  {run_dir}")
    L.append(f"Time windows:      {len(s['windows'])} graphs over "
             f"{len({w['date'] for w in s['windows']})} dates")
    L.append(f"Event time range:  {ns_to_str(s['t_min'])}  ->  {ns_to_str(s['t_max'])}")
    L.append(f"Distinct nodes:    {len(nodes)}  (a node counts once even if it is in many windows)")
    L.append(f"Total edges:       {s['total_edges']}  (each edge = one event, summed over windows)")
    L.append("")
    L.append("== WHAT A NODE CONTAINS ==")
    L.append(f"Node attribute keys: {dict(s['node_attr_keys'])}")
    L.append("  node id    : index ID (may be stored as a string), the same across all windows and stages")
    L.append("  node_type  : subject (process) | file | netflow (socket)")
    L.append("  label      : the node's value; command line or path for subjects, file path for")
    L.append("               files, IP:port info for netflows (depends on construction config)")
    L.append("")
    for ntype, c in type_counts.most_common():
        labels = s["node_type_label_counts"][ntype]
        empty = labels.get("", 0)
        L.append(f"-- {ntype}: {c} nodes, {len(labels)} distinct labels, {empty} with empty label")
        L.append("   most common labels:")
        for lbl, k in labels.most_common(10):
            L.append(f"     {k:>8}  {short(lbl, 100) or '<empty>'}")
        top = sorted(((n, d) for n, d in nodes.items() if d["type"] == ntype),
                     key=lambda x: -(x[1]["in"] + x[1]["out"]))[:5]
        L.append("   highest-degree nodes (id, in, out, label):")
        for n, d in top:
            L.append(f"     {n:>10}  in={d['in']:<8} out={d['out']:<8} {short(d['label'], 80)}")
        L.append("")

    L.append("== WHAT AN EDGE CONTAINS ==")
    L.append(f"Edge attribute keys: {dict(s['edge_attr_keys'])}")
    L.append("  label      : event type (the values below)")
    L.append("  time       : event timestamp, nanoseconds since epoch")
    L.append("  event_uuid : ID of the original event in the database")
    L.append(f"  y          : edge label; values seen: {dict(s['y_values'])}")
    L.append("               (0 everywhere is expected: ground truth is applied later, by node ID)")
    L.append("")
    L.append(f"Possible edge labels ({len(s['edge_labels'])}):")
    for lbl, c in s["edge_labels"].most_common():
        L.append(f"  {c:>10}  {100 * c / max(s['total_edges'], 1):6.2f}%  {lbl}")
    L.append("")
    L.append("Edge schema (src_type -[label]-> dst_type):")
    for (a, l, b), c in s["edge_schema"].most_common():
        L.append(f"  {c:>10}  {a:>8} -[{l}]-> {b}")
    L.append("")

    sizes = sorted(s["windows"], key=lambda w: w["edges"])
    if sizes:
        L.append("== TIME WINDOWS ==")
        L.append(f"Edges per window: min={sizes[0]['edges']}  "
                 f"median={sizes[len(sizes) // 2]['edges']}  max={sizes[-1]['edges']}")
        L.append(f"Largest window:  {sizes[-1]['date']}/{sizes[-1]['window']}")
        L.append("Full list with indices (for --viz-window) in windows.csv")

    with open(os.path.join(out_dir, "summary.txt"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L[:40]))


# ----------------------------------------------------------------------------- visualization


def visualize(window, out_dir, max_nodes):
    from pyvis.network import Network

    G = torch.load(window["path"], weights_only=False)
    keep = set(G.nodes)
    note = ""
    if G.number_of_nodes() > max_nodes:
        deg = sorted(G.degree, key=lambda x: -x[1])[:max_nodes]
        keep = {n for n, _ in deg}
        note = f" (showing the {max_nodes} highest-degree of {G.number_of_nodes()} nodes)"

    net = Network(height="800px", width="100%", bgcolor="#1a1a1a", font_color="white",
                  directed=True, notebook=False)
    for n in keep:
        d = G.nodes[n]
        ntype = d.get("node_type", "?")
        net.add_node(
            str(n),
            label=short(d.get("label", "") or n, 30),
            title=f"id: {n}\ntype: {ntype}\nlabel: {d.get('label', '')}\n"
                  f"in: {G.in_degree(n)}  out: {G.out_degree(n)}",
            color=NODE_COLORS.get(ntype, "#999999"),
            shape={"subject": "dot", "file": "square", "netflow": "triangle"}.get(ntype, "dot"),
        )

    # Collapse parallel events (same src, dst, label) into one edge with a count
    agg = {}
    for u, v, d in G.edges(data=True):
        if u in keep and v in keep:
            key = (u, v, d.get("label", "?"))
            t = int(d.get("time", 0))
            if key not in agg:
                agg[key] = [0, t, t]
            agg[key][0] += 1
            agg[key][1] = min(agg[key][1], t)
            agg[key][2] = max(agg[key][2], t)
    for (u, v, lbl), (count, t0, t1) in agg.items():
        net.add_edge(
            str(u), str(v),
            label=lbl.replace("EVENT_", ""),
            title=f"{lbl} x{count}\nfirst: {ns_to_str(t0)}\nlast:  {ns_to_str(t1)}",
            value=count,
        )

    net.barnes_hut(gravity=-10000, central_gravity=0.3, spring_length=120,
                   spring_strength=0.05, damping=0.9)
    net.set_edge_smooth("dynamic")
    safe = window["window"].replace(" ", "_").replace(":", "-").replace("~", "__")
    out = os.path.join(out_dir, f"viz_{safe}.html")
    net.write_html(out)
    print(f"Visualization{note}: {out}")


# ----------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, help="e.g. CADETS_E3")
    ap.add_argument("--hash", required=True, help="construction hash (a unique prefix is enough)")
    ap.add_argument("--artifacts", default="/home/artifacts", help="artifacts root folder")
    ap.add_argument("--dates", default="", help="comma-separated dates to include (default: all)")
    ap.add_argument("--viz-window", type=int, default=0,
                    help="index of the window to visualize (see windows.csv); -1 to skip")
    ap.add_argument("--viz-max-nodes", type=int, default=300,
                    help="cap on nodes drawn; the highest-degree nodes are kept")
    ap.add_argument("--out", default="construction_graphs", help="output root folder")
    args = ap.parse_args()

    run_dir = find_run_dir(args.artifacts, args.dataset, args.hash)
    run_hash = os.path.basename(run_dir)
    dates = {d.strip() for d in args.dates.split(",") if d.strip()}
    files = list_graph_files(run_dir, dates)
    if not files:
        sys.exit(f"No graph files found under {os.path.join(run_dir, 'nx')}")

    out_dir = os.path.join(args.out, f"{args.dataset}_{run_hash}")
    os.makedirs(out_dir, exist_ok=True)

    stats = collect_stats(files)
    write_outputs(stats, out_dir, args.dataset, run_dir)

    if args.viz_window >= 0:
        if args.viz_window >= len(stats["windows"]):
            print(f"--viz-window {args.viz_window} out of range (0..{len(stats['windows']) - 1})")
        else:
            visualize(stats["windows"][args.viz_window], out_dir, args.viz_max_nodes)

    print(f"\nAll outputs in: {out_dir}")


if __name__ == "__main__":
    main()