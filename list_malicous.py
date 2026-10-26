"""List the malicious nodes and edges of one PIDSMaker construction run.

Run from the PIDSMaker root, inside the PIDSMaker environment (it needs the database):

    python list_malicious.py <model> <dataset> --hash <construction_hash> [pidsmaker overrides...]

    python list_malicious.py kairos CADETS_E3 --hash 3fa9c1
    python list_malicious.py kairos CADETS_E3 --hash 3fa9c1 --all-dates
    python list_malicious.py kairos CADETS_E3 --hash 3fa9c1 --edge-selection either_node

<model> is only used to load the same config as your run (ground-truth version, edge selection
rule, mimicry settings). Any extra --section.key=value argument is passed to PIDSMaker's config,
exactly like on main.py.

Ground truth comes from PIDSMaker's own functions in pidsmaker/utils/labelling.py:
    get_ground_truth(cfg)          -> malicious node IDs (+ their GT labels and UUIDs)
    get_GP_of_each_attack(cfg)     -> malicious node IDs and time range per attack
    get_attack_to_mal_edges(cfg)   -> malicious edges per attack (only used for edge-CSV datasets)

Outputs, in construction_graphs/<dataset>_<hash>/malicious/:
    summary.txt               overview per attack and per time window
    malicious_nodes.csv       one row per ground-truth node, with where it appears
    malicious_edges.csv       every malicious edge found in the construction graphs
    attacks.csv               one row per attack
    windows.csv               malicious node/edge counts per time window
    malicious.json            node IDs and edge keys, ready to load in other scripts
"""

import argparse
import collections
import csv
import glob
import json
import os
import sys
from datetime import datetime, timezone

import torch

from pidsmaker.config import get_runtime_required_args, get_yml_cfg
from pidsmaker.utils import labelling


# ----------------------------------------------------------------------------- helpers


def ns_to_str(ns):
    try:
        return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f UTC"
        )
    except (ValueError, OverflowError, OSError, TypeError):
        return str(ns)


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def parse_own_args():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--hash", required=True, help="construction hash (unique prefix is enough)")
    ap.add_argument("--all-dates", action="store_true",
                    help="scan train/val/test dates instead of test dates only")
    ap.add_argument("--out", default="construction_graphs", help="output root folder")
    ap.add_argument("--edge-selection", default=None,
                    choices=["src_node", "dst_node", "both_nodes", "either_node"],
                    help="rule for malicious edges (DARPA TC datasets); default: value in the "
                         "config, or src_node if the config value is missing/invalid")
    own, rest = ap.parse_known_args()
    return own, rest


def build_cfg(pidsmaker_args):
    """Builds the same cfg object main.py builds, from '<model> <dataset> [--x.y=z ...]'."""
    args, unknown = get_runtime_required_args(return_unknown_args=True, args=pidsmaker_args)
    if unknown:
        sys.exit(f"Unknown PIDSMaker arguments: {unknown}")
    return get_yml_cfg(args)


def point_cfg_to_run(cfg, run_hash):
    """Makes cfg.construction point to the run given by the hash, not the one the config hashes to."""
    base = os.path.join(cfg._artifact_dir, "construction", cfg.dataset.name, "construction")
    matches = [d for d in glob.glob(os.path.join(base, run_hash + "*")) if os.path.isdir(d)]
    if len(matches) != 1:
        found = sorted(os.path.basename(d) for d in glob.glob(os.path.join(base, "*")))
        sys.exit(f"Hash '{run_hash}' matched {len(matches)} runs in {base}. Available: {found}")
    run_dir = matches[0]
    cfg.construction._task_path = run_dir
    cfg.construction._graphs_dir = os.path.join(run_dir, "nx/")
    cfg.construction._mimicry_dir = os.path.join(run_dir, "mimicry/")
    return run_dir


# ----------------------------------------------------------------------------- edge rules


VALID_SELECTIONS = ("src_node", "dst_node", "both_nodes", "either_node")


def resolve_edge_selection(cfg, override):
    """Returns the edge-selection rule to use, without crashing on a missing/invalid config value."""
    if override:
        return override
    try:
        value = cfg.evaluation.edge_evaluation.malicious_edge_selection
    except AttributeError:
        value = None
    if value in VALID_SELECTIONS:
        return value
    print(f"WARNING: evaluation.edge_evaluation.malicious_edge_selection is {value!r} in this "
          f"config, which is not one of {VALID_SELECTIONS}. Using 'src_node' (PIDSMaker's "
          f"default). Pass --edge-selection to choose explicitly.")
    return "src_node"


def make_edge_checker(cfg, attacks, attack_to_mal_edges, selection):
    """Returns f(src, dst, time, label) -> list of attack indices that make this edge malicious.

    Mirrors PIDSMaker's definition (labelling.get_attack_to_mal_edges):
      * CSV edge ground truth (ground_truth_edges_relative_path set): an edge is malicious if
        (src_id, dst_id, event_type) is listed for an attack. No timestamp involved.
      * Otherwise (DARPA TC): an edge is malicious for an attack if its time is inside the
        attack's time window and its endpoints satisfy
        evaluation.edge_evaluation.malicious_edge_selection with respect to that attack's
        ground-truth nodes. This rule is applied to the graph edges directly instead of matching
        DB timestamps, because construction may fuse repeated events (construction.fuse_edge),
        so a graph edge does not always carry the exact timestamp of every DB event.
    """
    if labelling._has_edge_csvs(cfg):
        lookup = collections.defaultdict(list)
        for a, edges in attack_to_mal_edges.items():
            for s, d, et in edges:
                lookup[(str(s), str(d), et)].append(a)

        def check(src, dst, t, label):
            return lookup.get((str(src), str(dst), label), [])

        return check, "csv"

    rules = {
        "src_node": lambda s, d, gt: s in gt,
        "dst_node": lambda s, d, gt: d in gt,
        "both_nodes": lambda s, d, gt: s in gt and d in gt,
        "either_node": lambda s, d, gt: s in gt or d in gt,
    }
    rule = rules[selection]
    attack_sets = {a: ({str(n) for n in info["nids"]}, *info["time_range"])
                   for a, info in attacks.items()}

    def check(src, dst, t, label):
        hits = []
        for a, (gt, start, end) in attack_sets.items():
            if start < int(t) < end and rule(str(src), str(dst), gt):
                hits.append(a)
        return hits

    return check, f"rule:{selection}"


# ----------------------------------------------------------------------------- scan


def scan_graphs(cfg, dates, gt_nids, node_to_attacks, check_edge):
    files = []
    for date in dates:
        for path in sorted(glob.glob(os.path.join(cfg.construction._graphs_dir, f"graph_{date}", "*"))):
            files.append((date, os.path.basename(path), path))
    if not files:
        sys.exit(f"No graphs for dates {dates} in {cfg.construction._graphs_dir}")

    node_seen = collections.defaultdict(list)  # nid -> [window names]
    node_info = {}  # nid -> (type, label) as stored in the graph
    edges = []
    windows = []
    gt_str = {str(n) for n in gt_nids}

    for i, (date, name, path) in enumerate(files):
        print(f"[{i + 1}/{len(files)}] {date}/{name}", flush=True)
        G = torch.load(path, weights_only=False)

        mal_here = [n for n in G.nodes if str(n) in gt_str]
        for n in mal_here:
            node_seen[int(n)].append(name)
            node_info[int(n)] = (G.nodes[n].get("node_type", ""), G.nodes[n].get("label", ""))

        n_mal_edges = 0
        for u, v, d in G.edges(data=True):
            t = d.get("time", 0)
            hits = check_edge(u, v, t, d.get("label"))
            if not hits:
                continue
            n_mal_edges += 1
            edges.append({
                "attacks": hits, "date": date, "window": name,
                "src": int(u), "src_type": G.nodes[u].get("node_type", ""),
                "src_label": G.nodes[u].get("label", ""), "src_is_gt": str(u) in gt_str,
                "dst": int(v), "dst_type": G.nodes[v].get("node_type", ""),
                "dst_label": G.nodes[v].get("label", ""), "dst_is_gt": str(v) in gt_str,
                "edge_label": d.get("label", ""), "time": int(t),
                "event_uuid": d.get("event_uuid", ""),
            })

        windows.append({
            "index": i, "date": date, "window": name, "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(), "mal_nodes": len(mal_here), "mal_edges": n_mal_edges,
        })

    return node_seen, node_info, edges, windows


# ----------------------------------------------------------------------------- main


def main():
    own, rest = parse_own_args()
    cfg = build_cfg(rest)
    run_dir = point_cfg_to_run(cfg, own.hash)
    run_hash = os.path.basename(run_dir)
    dataset = cfg.dataset.name

    out_dir = os.path.join(own.out, f"{dataset}_{run_hash}", "malicious")
    os.makedirs(out_dir, exist_ok=True)

    print("Loading ground truth with PIDSMaker's labelling functions...")
    gt_nids, gt_labels, uuid_to_nid = labelling.get_ground_truth(cfg)
    nid_to_uuid = {int(v): k for k, v in uuid_to_nid.items()}
    attacks = labelling.get_GP_of_each_attack(cfg)
    attack_files = [p for p, _, _ in labelling.ground_truth_attacks(cfg)]
    # Explicit edge lists only exist for datasets with edge CSVs. For DARPA TC datasets the
    # edges are derived from the nodes (see make_edge_checker), so the slow DB query in
    # labelling.get_attack_to_mal_edges is not needed.
    if labelling._has_edge_csvs(cfg):
        attack_to_mal_edges = labelling.get_attack_to_mal_edges(cfg)
    else:
        attack_to_mal_edges = {}
    selection = resolve_edge_selection(cfg, own.edge_selection)

    node_to_attacks = collections.defaultdict(list)
    for a, info in attacks.items():
        for n in info["nids"]:
            node_to_attacks[int(n)].append(a)

    check_edge, edge_mode = make_edge_checker(cfg, attacks, attack_to_mal_edges, selection)

    dates = (cfg.dataset.train_dates + cfg.dataset.val_dates + cfg.dataset.test_dates
             if own.all_dates else cfg.dataset.test_dates)
    node_seen, node_info, edges, windows = scan_graphs(
        cfg, dates, gt_nids, node_to_attacks, check_edge)

    # ---- malicious_nodes.csv
    node_rows = []
    for n in sorted(gt_nids):
        ntype, glabel = node_info.get(n, ("", ""))
        seen = node_seen.get(n, [])
        node_rows.append([
            n, nid_to_uuid.get(n, ""), ntype, glabel, gt_labels.get(n, ""),
            ";".join(map(str, node_to_attacks.get(n, []))), len(seen) > 0, len(seen),
            seen[0] if seen else "", seen[-1] if seen else "",
        ])
    write_csv(os.path.join(out_dir, "malicious_nodes.csv"),
              ["node_id", "uuid", "node_type", "graph_label", "ground_truth_label", "attacks",
               "in_scanned_graphs", "num_windows", "first_window", "last_window"], node_rows)

    # ---- malicious_edges.csv
    write_csv(os.path.join(out_dir, "malicious_edges.csv"),
              ["attacks", "date", "window", "src_id", "src_type", "src_label", "src_is_gt",
               "edge_label", "dst_id", "dst_type", "dst_label", "dst_is_gt", "time_ns",
               "time_utc", "event_uuid"],
              [[";".join(map(str, e["attacks"])), e["date"], e["window"], e["src"], e["src_type"],
                e["src_label"], e["src_is_gt"], e["edge_label"], e["dst"], e["dst_type"],
                e["dst_label"], e["dst_is_gt"], e["time"], ns_to_str(e["time"]), e["event_uuid"]]
               for e in edges])

    # ---- attacks.csv
    attack_rows = []
    for a, info in attacks.items():
        nids = {int(n) for n in info["nids"]}
        attack_rows.append([
            a, attack_files[a] if a < len(attack_files) else "",
            ns_to_str(info["time_range"][0]), ns_to_str(info["time_range"][1]), len(nids),
            sum(1 for n in nids if n in node_seen),
            sum(1 for e in edges if a in e["attacks"]),
            len(attack_to_mal_edges[a]) if a in attack_to_mal_edges else "",
        ])
    write_csv(os.path.join(out_dir, "attacks.csv"),
              ["attack", "ground_truth_file", "start_utc", "end_utc", "gt_nodes",
               "gt_nodes_in_graphs", "mal_edges_in_graphs", "mal_edges_in_edge_csv"],
              attack_rows)

    # ---- windows.csv
    write_csv(os.path.join(out_dir, "windows.csv"),
              ["index", "date", "window", "nodes", "edges", "malicious_nodes", "malicious_edges"],
              [[w["index"], w["date"], w["window"], w["nodes"], w["edges"], w["mal_nodes"],
                w["mal_edges"]] for w in windows])

    # ---- malicious.json (for perturbation scripts etc.)
    with open(os.path.join(out_dir, "malicious.json"), "w") as f:
        json.dump({
            "dataset": dataset, "construction_hash": run_hash, "edge_mode": edge_mode,
            "ground_truth_version": cfg.evaluation.ground_truth_version,
            "malicious_nodes": sorted(gt_nids),
            "attacks": {a: sorted(int(n) for n in info["nids"]) for a, info in attacks.items()},
            "malicious_edges": [[e["src"], e["dst"], e["edge_label"], e["time"]] for e in edges],
        }, f, indent=1)

    # ---- summary.txt
    L = [
        f"Dataset:               {dataset}",
        f"Construction run:      {run_dir}",
        f"Ground-truth version:  {cfg.evaluation.ground_truth_version}",
        f"Edge definition:       {edge_mode}",
        f"Dates scanned:         {', '.join(dates)}",
        "",
        f"Ground-truth nodes:    {len(gt_nids)}",
        f"  present in graphs:   {len(node_seen)}",
        f"  absent from graphs:  {len(gt_nids) - len(node_seen)} "
        "(no events in the scanned windows, or filtered out during construction)",
        f"Malicious edges found: {len(edges)}",
        "",
        "Per node type (present in graphs):",
    ]
    for t, c in collections.Counter(node_info[n][0] for n in node_seen).most_common():
        L.append(f"  {t:>8}: {c}")
    L.append("")
    L.append("Malicious edges per event type:")
    for lbl, c in collections.Counter(e["edge_label"] for e in edges).most_common():
        L.append(f"  {c:>8}  {lbl}")
    L.append("")
    L.append("Attacks:")
    for r in attack_rows:
        L.append(f"  [{r[0]}] {r[1]}")
        L.append(f"      {r[2]} -> {r[3]}")
        L.append(f"      GT nodes: {r[4]} ({r[5]} in graphs), malicious edges in graphs: {r[6]}")
    L.append("")
    L.append("Time windows containing malicious activity:")
    for w in windows:
        if w["mal_nodes"] or w["mal_edges"]:
            L.append(f"  [{w['index']:>3}] {w['window']}: {w['mal_nodes']} malicious nodes, "
                     f"{w['mal_edges']} malicious edges (of {w['edges']})")
    with open(os.path.join(out_dir, "summary.txt"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n" + "\n".join(L))
    print(f"\nAll outputs in: {out_dir}")


if __name__ == "__main__":
    main()