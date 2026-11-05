"""
PIDSMaker's construction stage does not produce one graph per dataset: 
it splits the event stream into fixed-length time windows 
(construction.time_window_size, 15 minutes for MAGIC) and builds a 
separate directed multigraph (networkx.MultiDiGraph) for each window. 
Each graph is stored as its own file, named after the window's start
and end time, in a folder for its date. In these graphs, nodes are 
system entities (processes, files and network sockets) and edges are individual 
events between them (reads, writes, executions, connections, and so on),
each with its timestamp and event type.

Node IDs are global: the same entity has the same ID in every window and
at every stage of the pipeline, and it appears in every window in which it
takes part in at least one event. Edges, by contrast, belong to exactly one
window, since each event occurs at a single point in time. The mal_perturbation
transformation is applied independently to each test-window graph. 

"""

import random
import networkx as nx
import wandb
import collections
from pidsmaker.utils.utils import log
from pidsmaker.utils.labelling import get_ground_truth


# =============================================================================
# 1. Module state
# =============================================================================

_STATS = collections.Counter()

_CACHE = {
    # # Experiment config
    # ('CADETS_E3', 'orthrus') : {
    #     'nids': [147459, 356868, 147460, 147461, 2446982, 2609543, 26254, 355470, 337550, 370961, 140956, 140957, 355357, 354975, 140960, 26277, 2444455, 354935, 26281, 337065, 381102, 355247, 355502, 355507, 2609587, 2609590, 141183, 355640, 355641, 370873, 2442683, 147515, 354877, 370874, 1219519, 211776, 370875, 370876, 354940, 355657, 26318, 355535, 370896, 370897, 370898, 2445651, 370899, 2446677, 418674, 370903, 336472, 370904, 379482, 141147, 336477, 2446308, 141285, 355176, 355439, 355056, 2445298, 379506, 355572, 26357, 228725, 355447, 380024, 355316, 354938, 2447478, 354933, 2442623], 
    #     'nids_str': ["147459", "356868", "147460", "147461", "2446982", "2609543", "26254", "355470", "337550", "370961", "140956", "140957", "355357", "354975", "140960", "26277", "2444455", "354935", "26281", "337065", "381102", "355247", "355502", "355507", "2609587", "2609590", "141183", "355640", "355641", "370873", "2442683", "147515", "354877", "370874", "1219519", "211776", "370875", "370876", "354940", "355657", "26318", "355535", "370896", "370897", "370898", "2445651", "370899", "2446677", "418674", "370903", "336472", "370904", "379482", "141147", "336477", "2446308", "141285", "355176", "355439", "355056", "2445298", "379506", "355572", "26357", "228725", "355447", "380024", "355316", "354938", "2447478", "354933", "2442623"], 
    #     'labels': {211776: "{'subject': 'None nginx'}", 26277: "{'netflow': '128.55.12.73:80->81.49.200.166:43530'}", 26281: "{'netflow': '128.55.12.73:38265->200.36.109.214:80'}", 26254: "{'netflow': '128.55.12.73:80->81.49.200.166:44623'}", 26318: "{'netflow': '128.55.12.73:19857->139.123.0.113:80'}", 26357: "{'netflow': '128.55.12.73:17330->61.167.39.128:80'}", 228725: "{'subject': 'None vUgefal'}", 1219519: "{'file': '/tmp/vUgefal'}", 2446982: "{'file': '/tmp/main'}", 355470: "{'subject': 'None main'}", 337550: "{'subject': 'None nginx'}", 140956: "{'netflow': '128.55.12.73:80->25.159.96.207:45203'}", 140957: "{'netflow': '128.55.12.73:46517->76.56.184.25:80'}", 355357: "{'subject': 'None XIM'}", 354975: "{'subject': 'None tmux-1002'}", 140960: "{'netflow': '128.55.12.73:12680->155.162.39.48:80'}", 2444455: "{'file': '/tmp/minions'}", 354935: "{'subject': 'None python2.7'}", 337065: "{'subject': 'None sendmail'}", 381102: "{'file': '/var/log/salt/minion'}", 355247: "{'subject': 'None minions'}", 355502: "{'subject': 'None sendmail'}", 355507: "{'subject': 'None sendmail'}", 141183: "{'netflow': '128.55.12.73:39242->53.158.101.118:80'}", 355641: "{'subject': 'None test'}", 2442683: "{'file': '/var/cache/salt/minion/proc/20180412180113291397'}", 354877: "{'subject': 'None top'}", 355657: "{'subject': 'None test'}", 355535: "{'subject': 'None test'}", 2445651: "{'file': '/tmp/XIM'}", 2446677: "{'file': '/var/log/sendmail'}", 336472: "{'subject': 'None python2.7'}", 379482: "{'file': 'None'}", 141147: "{'netflow': '128.55.12.73:60746->53.158.101.118:80'}", 336477: "{'subject': 'None sendmail'}", 2446308: "{'file': '/var/log/netlog'}", 141285: "{'netflow': '128.55.12.73:34345->192.113.144.28:80'}", 355176: "{'subject': 'None minions'}", 355439: "{'subject': 'None sendmail'}", 355056: "{'subject': 'None tmux-1002'}", 2445298: "{'file': '/tmp/font'}", 379506: "{'file': 'None'}", 355572: "{'subject': 'None test'}", 355316: "{'subject': 'None XIM'}", 2447478: "{'file': '/tmp/test'}", 355447: "{'subject': 'None sendmail'}", 380024: "{'file': '/dev/random'}", 354933: "{'subject': 'None python2.7'}", 354938: "{'subject': 'None sendmail'}", 354940: "{'subject': 'None sendmail'}", 2442623: "{'file': '/tmp/tmux-1002'}", 147459: "{'netflow': '128.55.12.73:80->25.159.96.207:58625'}", 147460: "{'netflow': '128.55.12.73:49722->76.56.184.25:80'}", 147461: "{'netflow': '128.55.12.73:27115->155.162.39.48:80'}", 356868: "{'subject': 'None nginx'}", 2609543: "{'file': '/tmp/pEja72mA'}", 370896: "{'subject': 'None sshd'}", 370961: "{'subject': 'None pEja72mA'}", 370897: "{'subject': 'None sshd'}", 370898: "{'subject': 'None sshd'}", 370899: "{'subject': 'None sshd'}", 370903: "{'subject': 'None mkdir'}", 370904: "{'subject': 'None wget'}", 147515: "{'netflow': '128.55.12.73:63341->53.158.101.118:80'}", 418674: "{'file': 'None'}", 2609587: "{'file': '/usr/home/user/eraseme'}", 2609590: "{'file': '/usr/home/user/eraseme/index.html'}", 355640: "{'subject': 'None sshd'}", 370873: "{'subject': 'None sshd'}", 370874: "{'subject': 'None sshd'}", 370875: "{'subject': 'None sshd'}", 370876: "{'subject': 'None sshd'}"}, 
    #     'uuid_to_nid': {'674D8313-390A-11E8-BF66-D9AA8AFF4A69': 211776, '60040266-39AE-11E8-BF66-D9AA8AFF4A69': 26277, '6034BA72-39AE-11E8-BF66-D9AA8AFF4A69': 26281, 'FFF277E0-39AD-11E8-BF66-D9AA8AFF4A69': 26254, 'D384652A-39AF-11E8-BF66-D9AA8AFF4A69': 26318, '323ED9A0-39B1-11E8-BF66-D9AA8AFF4A69': 26357, 'D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69': 228725, 'F77E454D-CA07-6B5D-87CA-9EFDCD6BA3ED': 1219519, '4DA445A7-56DB-D353-9B56-AD9CD3D373D6': 2446982, '5CD609A7-3E7F-11E8-A5CB-3FA3753A265A': 355470, '11C64B2C-3DC3-11E8-A5CA-3FA3753A265A': 337550, '5EE4F8FC-3E7B-11E8-A5CB-3FA3753A265A': 140956, '5EE54774-3E7B-11E8-A5CB-3FA3753A265A': 140957, '48289024-3E7E-11E8-A5CB-3FA3753A265A': 355357, 'C4F4FF22-3E7B-11E8-A5CB-3FA3753A265A': 354975, '5F12229C-3E7B-11E8-A5CB-3FA3753A265A': 140960, '74D78344-4A18-265B-984A-8D22BB26DDCF': 2444455, '7CF2DDA4-3E7B-11E8-A5CB-3FA3753A265A': 354935, '1AC05B7A-3DC3-11E8-A5CB-3FA3753A265A': 337065, '1902FFA3-6F80-2052-806F-3D6A2220819E': 381102, '7B30E76D-3E7D-11E8-A5CB-3FA3753A265A': 355247, 'AE11D308-3E7F-11E8-A5CB-3FA3753A265A': 355502, 'B2C5B97D-3E7F-11E8-A5CB-3FA3753A265A': 355507, '482AD2B6-3E7E-11E8-A5CB-3FA3753A265A': 141183, '327621AE-3E80-11E8-A5CB-3FA3753A265A': 355641, '60EBF436-633F-B75F-BF63-A8040FB73989': 2442683, '34612C08-3E7B-11E8-A5CB-3FA3753A265A': 354877, '47E61FFC-3E80-11E8-A5CB-3FA3753A265A': 355657, 'DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A': 355535, '5026C48F-56BA-3E5B-BA56-DD382B3EC82B': 2445651, 'CBBF8038-5237-8651-B752-A1C99186128A': 2446677, '1131CD42-3DC3-11E8-A5CA-3FA3753A265A': 336472, '51110606-D232-9652-B2D2-3A7242968F8A': 379482, '21A20E29-3E7E-11E8-A5CB-3FA3753A265A': 141147, '15FD3B4A-3DC3-11E8-A5CB-3FA3753A265A': 336477, 'E5F1BC5B-052D-3F5F-AD05-928A8F3FF746': 2446308, '47EA0B5C-3E80-11E8-A5CB-3FA3753A265A': 141285, '17C4C0C3-3E7D-11E8-A5CB-3FA3753A265A': 355176, '15267234-3E7F-11E8-A5CB-3FA3753A265A': 355439, '42E4A848-3E7C-11E8-A5CB-3FA3753A265A': 355056, 'F993C224-C6AD-AB5C-ADC6-09316CABFFD8': 2445298, '1633500B-D34B-8058-8BD3-ABB7D880915E': 379506, '0001A528-3E80-11E8-A5CB-3FA3753A265A': 355572, '219DE547-3E7E-11E8-A5CB-3FA3753A265A': 355316, '84D440C2-4E50-4A5C-904E-C4772C4ACD5A': 2447478, '1D3ACF79-3E7F-11E8-A5CB-3FA3753A265A': 355447, '416AB837-8E42-6D58-828E-6976586D8E68': 380024, '7CED5514-3E7B-11E8-A5CB-3FA3753A265A': 354933, '7D2E10B3-3E7B-11E8-A5CB-3FA3753A265A': 354938, '81E2003D-3E7B-11E8-A5CB-3FA3753A265A': 354940, '5453C813-1A0E-4359-8E1A-41B40943CDC5': 2442623, '937BA111-3F1B-11E8-A5CB-3FA3753A265A': 147459, '937BE863-3F1B-11E8-A5CB-3FA3753A265A': 147460, '93A2D6AC-3F1B-11E8-A5CB-3FA3753A265A': 147461, '11C65665-3DC3-11E8-A5CA-3FA3753A265A': 356868, 'E5A15412-68E0-FD54-A068-DD6114FD9040': 2609543, '042ADADF-3F1C-11E8-A5CB-3FA3753A265A': 370896, '4FB0BFEA-3F1C-11E8-A5CB-3FA3753A265A': 370961, '0433BCDC-3F1C-11E8-A5CB-3FA3753A265A': 370897, '044B097A-3F1C-11E8-A5CB-3FA3753A265A': 370898, '04632D66-3F1C-11E8-A5CB-3FA3753A265A': 370899, '0488BCD7-3F1C-11E8-A5CB-3FA3753A265A': 370903, '04A9D03C-3F1C-11E8-A5CB-3FA3753A265A': 370904, '4FB30E44-3F1C-11E8-A5CB-3FA3753A265A': 147515, '3209A26F-A6EF-0350-AFA6-B1BD1003D390': 418674, 'EC6F1E3C-792F-485D-AF79-1A832D489243': 2609587, '00C8E4E5-8BBC-D45B-BC8B-D32BABD4AFCE': 2609590, '2CA83801-3E80-11E8-A5CB-3FA3753A265A': 355640, 'E0C1A46B-3F1B-11E8-A5CB-3FA3753A265A': 370873, 'E0CAAC23-3F1B-11E8-A5CB-3FA3753A265A': 370874, 'E0E17EDD-3F1B-11E8-A5CB-3FA3753A265A': 370875, 'E0F82A6C-3F1B-11E8-A5CB-3FA3753A265A': 370876}
    # }
}


# =============================================================================
# 2. Graph format reference
# =============================================================================

# Example of the three nodes type we have in the Graphs
# ('node_id', {'node_type': 'subject | file | netflow', 'label': 'path cmd | path | None'})
# ('224730', {'node_type': 'subject', 'label': 'None sleep'})
# ('1181195', {'node_type': 'file', 'label': '/var/mail/edward.lock'})
# ('23445',{'node_type': 'netflow', 'label': '127.0.0.1'})

# Example of some edges that we have in the Graphs 
# edge_key dentifier that distinguishes edges between the same pair of no
# ('src_node_id', 'dst_node_id', edge_key, {'event_uuid': '...', 'time' : 'timestamp_when_event_occured', 'label': '...', 'y': always_0_labeling_gets_done_later})
# ('379482', '226802', 0, {'event_uuid': '21EE8D10-A623-5D31-8450-A2E9B8BA9968', 'time': 1523021856116312352, 'label': 'EVENT_OPEN', 'y': 0})
# ('379482', '226802', 1, {'event_uuid': '96AF63A8-69B7-5F9A-A547-600D30AA26AE', 'time': 1523021856126310773, 'label': 'EVENT_READ', 'y': 0})
# ('379482', '226803', 0, {'event_uuid': '5200417F-856A-50C1-BE52-34F2D6919614', 'time': 1523021913136309403, 'label': 'EVENT_READ', 'y': 0})


# =============================================================================
# 3. Ground truth and dates
# =============================================================================

def _malicious_ids(cfg):
    """"
    Saves with key (cfg.dataset.name, cfg.evaluation.ground_truth_version) _CACHE object that contains:

        * gt_nids: the set of malicious node IDs, the integer IDs used for nodes in the graphs.
        * gt_labels: a dictionary from each malicious node ID to its label in the ground-truth file (a process name, file path or IP address).
        * uuid_to_nid: a dictionary from each malicious nodes original database UUID to its node ID.
    Args:
        cfg: configuration object (a.k.a the .yml config + arguments passed in terminal)

    Returns
        A dict with the following keys:
            * "nids" : the set of malicious node IDs, the integer IDs used for nodes in the graphs 
            * nids_str:  String version of the IDs
            * "lables" : a dictionary from each malicious node ID to its label in the ground-truth file (a process name, file path or IP address).
            * "uuid_to_nid" : a dictionary from each malicious nodes original database UUID to its node ID.

    """
    key = (cfg.dataset.name, cfg.evaluation.ground_truth_version)
    if key not in _CACHE:
        gt_nids, gt_labels, uuid_to_nid = get_ground_truth(cfg)
        _CACHE[key] = { 
            "nids" : [int(n) for n in gt_nids],
            "nids_str" : {str(n) for n in gt_nids},
            "labels" : {int(n): label for n, label in gt_labels.items()},
            "uuid_to_nid": {uuid: int(n) for uuid, n in uuid_to_nid.items()}
        }
        log(f"[mal_pertubation] loaded {len(_CACHE[key]['nids'])} malicious node IDs for {key}")
    return _CACHE[key]


def _malicious_nodes_in_graph(G: nx.MultiDiGraph, cfg) -> set[str]:
    """
    Returns the malicious nodes present in this graph.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        cfg: Full PIDSMaker config (the .yml config + command-line overrides), as
            built by get_yml_cfg. Must contain cfg.dataset and cfg.transformation.
 
    Returns:
        set[str] of the ground-truth node IDs found in G, e.g. {'147459', '355470'};
        empty if the window contains no malicious node.
    """
    all_mal = _malicious_ids(cfg)["nids_str"]
    return {n for n in G.nodes if n in all_mal}


def dates_to_perturb(cfg) -> list[str]:
    """
    Returns the dates whose graphs are perturbed, according to p.split.
 
    Called once by transformation.py, before its loop over dates.
 
    Args:
        cfg: Full PIDSMaker config (the .yml config + command-line overrides), as
            built by get_yml_cfg. Must contain cfg.dataset and cfg.transformation.
 
    Returns:
        list[str] of dates, e.g. ['2018-04-06', '2018-04-11'], taken from
        "train" -> train_dates, "val" -> val_dates, "train_val" -> both, "test" -> test_dates.
 
    Raises:
        ValueError: if p.split is not one of the values above.
    """
    split = cfg.transformation.mal_perturbation.split
    d = cfg.dataset
    split_to_dates = {
        "train": list(d.train_dates),
        "val": list(d.val_dates),
        "train_val": list(d.train_dates) + list(d.val_dates),
        "test": list(d.test_dates),
    }
    if split not in split_to_dates:
        raise ValueError(f"Unknown mal_perturbation.split: {split!r} "
                         f"(expected one of {list(split_to_dates)})")
    dates = split_to_dates[split]
    log(f"[mal_perturbation] split={split}: perturbing {len(dates)} dates {dates}")
    return dates


# =============================================================================
# 4. Candidate edges (WHAT can be lost)
# =============================================================================

def _incident_edges(G: nx.Graph, mal_nodes : list[str], dir: str):
    """
    Receives a graph, a list of malicous nodes ids (as strings) and a the direction of edges (in, out or all).

    Args:
        G: MultiDiGraph instance
        mal_nodes: list that contains all malicous nodes ids present in the dataset (not just this graph, the full dataset)
        dir: indicates the direction of edges we are interested ("in", "out" or "all")

    Returns: 
        An object with the following keys:
            *  "inbound_edges" : OutMultiEdgeView that contains all inbound edges of the malicious nodes
            present in the given graph
            * "outbound_edges" : OutMultiEdgeView that contains all outbound edges of the malicious nodes 
            present in the given graph
    """
    log(f"    Finding {dir} edges that are touching malicous nodes: {mal_nodes}")
    in_edges = []
    out_edges =[]

    if(dir=="in" or dir=="both"):
        in_edges = G.in_edges(mal_nodes, keys=True, data=True)
    if(dir=="out" or dir=="both"):
        out_edges = G.out_edges(mal_nodes, keys=True, data=True)

    log(f"    Total Incoming edges: {len(in_edges)}")
    log(f"    Total Outgoing edges: {len(out_edges)}")

    return { "inbound_edges" : in_edges , "outbound_edges" : out_edges}



def _is_malicious_edge(u: str, v: str, mal_nodes: set[str], rule: str) -> bool:
    """
    Says whether the edge u -> v counts as malicious under an edge rule.
 
    Args:
        u: Source node ID (str).
        v: Destination node ID (str).
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
        rule: p.edge_rule, one of:
            "src_node" (u malicious), "dst_node" (v malicious),
            "both_nodes" (u and v malicious, the attack chain), "either_node" (u or v).
 
    Returns:
        bool.
 
    Raises:
        ValueError: for an unknown rule.
    """
    if rule == "src_node":
        return u in mal_nodes
    if rule == "dst_node":
        return v in mal_nodes
    if rule == "both_nodes":
        return u in mal_nodes and v in mal_nodes
    if rule == "either_node":
        return u in mal_nodes or v in mal_nodes
    
    raise ValueError(f"Unknown mal_perturbation.edge_rule: {rule}")


def _matches_edge_types(data: dict, edge_types: str) -> bool:
    """
    Says whether an edge passes the p.edge_types filter.
 
    Args:
        data: The edge's attribute dict, e.g. {"label": "EVENT_READ", "time": ..., ...}.
        edge_types: p.edge_types, comma-separated event types, e.g. "EVENT_READ,EVENT_WRITE".
            Empty or None means all types.
 
    Returns:
        bool: True if the edge's "label" is listed, or if no types are listed.
    """
    wanted = _parse_list(edge_types)

    return not wanted or data.get("label") in wanted

def _parse_list(value) -> list[str]:
    """
    Turns a comma-separated string into a list.
 
    Args:
        value: e.g. "EVENT_READ, EVENT_WRITE"; None or "" allowed.
 
    Returns:
        list[str], e.g. ['EVENT_READ', 'EVENT_WRITE']; [] for None or "".
    """
    if not value:
        return []
    return [x.strip() for x in str(value).split(",") if x.strip()]


def _edge_sort_key(edge: tuple):
    """
    Sort key giving edges a fixed order (numeric node IDs, then key).
 
    Used before every random or score-based choice, so the same seed always gives
    the same result.
 
    Args:
        edge: (u, v, key) tuple, e.g. ('379482', '226802', 1).
 
    Returns:
        tuple usable as a sort key.
    """
    u, v, k = edge[0], edge[1], edge[2]
    try:
        return (0, int(u), int(v), k)
    except (TypeError, ValueError):
        return (1, str(u), str(v), k)

def _candidate_edges(G: nx.MultiDiGraph, mal_nodes: set[str], p) -> list[tuple]:
    """
    Returns the edges that may be lost (the denominator of X%).
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
            Uses p.target ("malicious": edges accepted by p.edge_rule;
            "benign": edges touching no malicious node; "all": every edge)
            and p.edge_types.
 
    Returns:
        list of (u, v, key) tuples, e.g. [('379482', '226802', 0)], in a fixed order.
 
    Raises:
        ValueError: for an unknown p.target or p.edge_rule.
    """
    target = p.target
    if target not in ("malicious", "benign", "all"):
        raise ValueError(f"Unknown mal_perturbation.target: {target!r}")
 
    candidates = []
    for u, v, k, data in G.edges(keys=True, data=True):
        if not _matches_edge_types(data, p.edge_types):
            continue
        if target == "malicious" and not _is_malicious_edge(u, v, mal_nodes, p.edge_rule):
            continue
        if target == "benign" and (u in mal_nodes or v in mal_nodes):
            continue
        candidates.append((u, v, k))
 
    candidates.sort(key=_edge_sort_key)
    return candidates




# =============================================================================
# 5. Selection (WHICH candidates are lost)
# =============================================================================

def _select(G: nx.MultiDiGraph, candidates: list[tuple], p, rng: random.Random, mal_nodes: set[str]) -> list[tuple]:
    """
    Chooses which candidate edges are lost, according to p.selection.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)], from _candidate_edges.
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
            Uses p.selection ("random", "burst", or a score in SCORERS) and p.fraction.
        rng: random.Random seeded with p.seed, used for every random choice.
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        The chosen edges, a subset of candidates (list of (u, v, key) tuples, e.g. [('379482', '226802', 0)]).
 
    Raises:
        ValueError: for an unknown selection.
    """
    if not candidates:
        return []
    if p.selection == "random":
        return _select_random(candidates, p.fraction, rng)
    if p.selection == "burst":
        return _select_burst(G, candidates, p.fraction, rng)
    if p.selection in SCORERS:
        return _select_top_scored(G, candidates, p.fraction, SCORERS[p.selection], p, mal_nodes)
    raise ValueError(f"Unknown mal_perturbation.selection: {p.selection!r} "
                     f"(expected random, burst or one of {list(SCORERS)})")


def _num_to_remove(n_candidates: int, fraction: float) -> int:
    """
    Computes how many candidates are lost: k = round(n_candidates * fraction).
 
    Args:
        n_candidates: Number of candidates.
        fraction: p.fraction, between 0.0 and 1.0.
 
    Returns:
        int between 0 and n_candidates.
 
    Raises:
        ValueError: if fraction is None or outside 0-1.
    """
    if fraction is None:
        raise ValueError("mal_perturbation.fraction is not set")
    if not 0.0 <= fraction <= 1.0:
        raise ValueError(f"mal_perturbation.fraction must be between 0 and 1, got {fraction}")
    return max(0, min(n_candidates, round(n_candidates * fraction)))


def _select_random(candidates: list[tuple], fraction: float, rng: random.Random) -> list[tuple]:
    """
    Realistic loss: picks k candidates at random.
 
    Args:
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        fraction: p.fraction, share of candidates to pick.
        rng: random.Random seeded with p.seed, used for every random choice.
 
    Returns:
        k distinct edges from candidates; the same seed gives the same edges.
    """
    ordered = sorted(candidates, key=_edge_sort_key)
    k = _num_to_remove(len(ordered), fraction)
    return rng.sample(ordered, k)

def _select_burst(G: nx.MultiDiGraph, candidates: list[tuple], fraction: float, rng: random.Random) -> list[tuple]:
    """
    Capture outage: picks every candidate inside one random time interval.
 
    The interval covers `fraction` of the window's time span (min to max edge time),
    so the number picked is approximately, not exactly, k.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        fraction: p.fraction, share of the window's duration covered by the outage.
        rng: random.Random seeded with p.seed, used for every random choice.
 
    Returns:
        The candidates whose "time" falls inside the interval.
    """

    _num_to_remove(len(candidates), fraction)  # only validates fraction
    if fraction == 0.0:
        return []
    times = [int(d["time"]) for _, _, d in G.edges(data=True)]
    t_min, t_max = min(times), max(times)
    length = (t_max - t_min) * fraction
    start = t_min + rng.random() * ((t_max - t_min) - length)
    end = start + length
    return [e for e in sorted(candidates, key=_edge_sort_key)
            if start <= int(G.edges[e]["time"]) <= end]


def _select_top_scored(    G: nx.MultiDiGraph, candidates: list[tuple], fraction: float, score_fn, p, mal_nodes: set[str]) -> list[tuple]:
    """
    Worst-case loss: picks the k highest-scoring candidates.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        fraction: p.fraction, share of candidates to pick.
        score_fn: One of the SCORERS functions, called as
            score_fn(G, candidates, p, mal_nodes) -> {edge: score}.
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        The k candidates with the highest scores (ties broken by the fixed edge order).
   """
    k = _num_to_remove(len(candidates), fraction)
    scores = score_fn(G, candidates, p, mal_nodes)
    ranked = sorted(candidates, key=lambda e: (-scores.get(e, 0.0), _edge_sort_key(e)))
    return ranked[:k]


# =============================================================================
# 6. Importance scores (used by _select_top_scored); higher = more important
#    Each takes (G, candidates, p, mal_nodes) and returns {edge: score}, so the
#    graph-wide work (degrees, betweenness, counts) is done once per window.
# =============================================================================

def _score_degree(G: nx.MultiDiGraph, candidates: list[tuple], p, mal_nodes: set[str]) -> dict:
    """
    Structural score: degree(u) + degree(v) for each candidate edge.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        dict mapping each candidate to its score (float), e.g. {('1', '3', 0): 6.0}.
    """
    deg = dict(G.degree())
    return {e: float(deg[e[0]] + deg[e[1]]) for e in candidates}


def _score_betweenness(G: nx.MultiDiGraph, candidates: list[tuple], p, mal_nodes: set[str]) -> dict:
    """
    Structural score: edge betweenness on an undirected, simplified copy of G.
 
    With malicious nodes, computed only within p.ego_radius hops of them (edges outside
    score 0); without (training side), estimated on the whole window from 200 sampled
    source nodes, seeded with p.seed.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
            Uses p.ego_radius and p.seed.
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        dict mapping each candidate to its score (float); parallel edges share a score.
    """
    H = nx.Graph(G.to_undirected(as_view=True))  # merges parallel edges and directions
    if mal_nodes:
        radius = p.ego_radius or 2
        keep = set()
        for n in mal_nodes:
            keep |= set(nx.single_source_shortest_path_length(H, n, cutoff=radius))
        H = H.subgraph(keep)
        eb = nx.edge_betweenness_centrality(H)
    else:
        sample = min(200, H.number_of_nodes())
        eb = nx.edge_betweenness_centrality(H, k=sample, seed=p.seed) if sample else {}
    eb = {frozenset(pair): score for pair, score in eb.items()}
    return {e: eb.get(frozenset((e[0], e[1])), 0.0) for e in candidates}


def _score_event_type(G: nx.MultiDiGraph, candidates: list[tuple], p, mal_nodes: set[str]) -> dict:
    """
    Attack-semantics score based on the edge's event type.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
            Uses p.important_event_types, e.g. "EVENT_EXECUTE,EVENT_WRITE": the first
            type listed scores highest; unlisted types score 0.
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        dict mapping each candidate to its score (float).
    """
    important = _parse_list(p.important_event_types)
    weight = {t: float(len(important) - i) for i, t in enumerate(important)}
    return {e: weight.get(G.edges[e].get("label"), 0.0) for e in candidates}


def _score_rarity(G: nx.MultiDiGraph, candidates: list[tuple], p, mal_nodes: set[str]) -> dict:
    """
    Anomaly score: rare (src node_type, event type, dst node_type) patterns score high.
 
    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        candidates: list of (u, v, key) tuples, e.g. [('379482', '226802', 0)].
        p: The perturbation parameters, cfg.transformation.mal_perturbation
            (fields such as p.fraction, p.seed, p.target; see config.py).
        mal_nodes: IDs (str) of the malicious nodes. Only used with `in`, so a set
            or a list both work, e.g. {'147459', '355470'}.
 
    Returns:
        dict mapping each candidate to 1 / (number of edges in G with the same pattern).
    """
    def pattern(u, v, data):
        return (G.nodes[u].get("node_type"), data.get("label"), G.nodes[v].get("node_type"))
 
    counts = collections.Counter(pattern(u, v, d) for u, v, d in G.edges(data=True))
    return {e: 1.0 / counts[pattern(e[0], e[1], G.edges[e])] for e in candidates}


SCORERS = {
    "degree": _score_degree,
    "betweenness": _score_betweenness,
    "event_type": _score_event_type,
    "rarity": _score_rarity,
}


# =============================================================================
# 7. Operations: node removal
# =============================================================================

def _remove_neighbors(G, mal_nodes, p, rng) -> nx.Graph: 
    """
        Removes neighours of malicious nodes from a graph. For the same <DATASET, MODEL, CONFIG> 
        the neighbours that are removed are the same.

        Args:
            G: MultiDiGraph instance
            mal_nodes: List of malicous nodes present in the dataset 
            p: Arguments that are going to be used has 'parameters' for the pertubations. The only 
            pertubation value used in this function are:  p.fraction (percantage of neighbours that
            are going to be removed) and p.seed (seed used for Random class to ensure reproducibility).
            rng: Random instance created with the p.seed 

        Returns:
            A graph with p.fraction of neighbours removed. 
    
    """
    log("*"*50 +"\n")
    log(f"    Removing malicious nodes neigbors (i.e. sucessors ) with the folowing config:\n{p}")
    candidate_neighbours = set()
    # Get candidate neigbours ids
    for node_id in mal_nodes:
        try:
            # log(f"Malicious Node with id [{node_id}] has attrs = {G.nodes[str(node_id)]}")
            for neighbor in G.neighbors(node_id):
                if neighbor not in mal_nodes:
                    candidate_neighbours.add(neighbor)
        except Exception as e:
            continue 
    
    if len(candidate_neighbours) == 0:
        log("*"*50 +"\n")
        return G
    
    # Sort list, so that the same seed always starts from the same order
    log(f"    Total number of candidate neighbours : {len(candidate_neighbours)}")
    log(f"    Ids of candidate neighbours : {candidate_neighbours}")
    s_candidate_neighbours = sorted(candidate_neighbours)

    # Calculate how many nodes we are going to remove
    k = round(len(s_candidate_neighbours) * p.fraction)

    # Remove the k random, distinct candidates (using the seed the rng to ensure seed reproducibility)
    neighbor_to_remove = rng.sample(s_candidate_neighbours,k)
    log(f"    Removing the following candidate neighbours = {neighbor_to_remove}")
    G.remove_nodes_from(neighbor_to_remove)
    log("*"*50 +"\n")

    return G


def _remove_network_nodes(G, mal_nodes, p, rng) -> nx.Graph:
    """Removes a p.fraction of non malicious network nodes from a graph"""
    log("*"*50 +"\n")
    log(f"    Removing network nodes from graph with the folowing config:\n{p}")
    network_nodes = []

    # E.g. of tuple ('221452', {'node_type': 'subject', 'label': 'None lsof'})
    # Get network nodes  ids
    for tuple in G.nodes.data():
        node_id = tuple[0]
        node_type = tuple[1]["node_type"] 
        if node_type == "netflow" and node_id not in mal_nodes:
            network_nodes.append(node_id)

    if len(network_nodes) == 0:
        log("*"*50 +"\n")
        return G


    # Sort list, so that the same seed always starts from the same order
    log(f"    Total number of networks nodes : {len(network_nodes)}")
    log(f"    Ids of network nodes : {network_nodes}")
    s_network_nodes = sorted(network_nodes)

    # Calculate how many nodes we are going to remove
    k = round(len(s_network_nodes) * p.fraction)

    # Remove the k random, distinct candidates (using the seed the rng to ensure seed reproducibility)
    nodes_to_remove = rng.sample(s_network_nodes,k)
    log(f"    Removing the following candidate neighbours = {nodes_to_remove}")
    G.remove_nodes_from(nodes_to_remove)
    log("*"*50 +"\n")
    return G


def _remove_subject_and_network(G, mal_nodes, p, rng) -> nx.Graph:
    """Removes a p.fraction of subject nodes that have an edge with a network node"""
    log("*"*50 +"\n")
    log(f"    Removing network nodes and first sucessor from graph with the folowing config:\n{p}")
    network_nodes = []

    # E.g. of tuple ('221452', {'node_type': 'subject', 'label': 'None lsof'})
    # Get network nodes  ids
    for tuple in G.nodes.data():
        node_id = tuple[0]
        node_type = tuple[1]["node_type"] 
        if node_type == "netflow" and node_id not in mal_nodes:
            network_nodes.append(node_id)

    if(len(network_nodes) == 0):
        log("*"*50 +"\n")
        return G 

    # Remove first successors of network nodes (i.e. remove subject nodes, except the malicious ones)
    for id in network_nodes:
        first_sucessors = [x for x in sorted(list(G.successors(id))) if x not in mal_nodes]


        if (len(first_sucessors) == 0):
            continue

        # Calculate how many nodes we are going to remove
        k = round(len(first_sucessors) * p.fraction)
       
        
        # Remove the k random, distinct candidates (using the seed the rng to ensure seed reproducibility)
        nodes_to_remove = rng.sample(first_sucessors,k)
        log(f"    Removing the following successors (a.k.a subject nodes) = {nodes_to_remove}")
        G.remove_nodes_from(nodes_to_remove)

    # Removing the network nodes
    log(f"    Removing the following network nodes = {network_nodes}")
    G.remove_nodes_from(network_nodes)


    log("*"*50 +"\n")

    return G 


def _remove_random_nodes(G, mal_nodes, p, rng) -> nx.Graph:
    """
    Removes a p.fraction of nodes that are of p.node_types (could remove more than one type, and
    tipicaly there are three types of node: subject, file, netflow.

    """
    log("*"*50 +"\n")
    log(f"    Removing random nodes with the folowing config:\n{p}")

    aux = {}    
    
    if p.node_types is not None:
        node_types = p.node_types.split(",")
        for type in node_types:
            aux[type] = []
    else: 
        aux = {"subject" : [], "file" : [], "netflow" : []}


    # Get ids of node types we want to remove
    for tuple in G.nodes.data():
        node_id = tuple[0]
        node_type = tuple[1]["node_type"] 
        if node_type not in aux or node_id in mal_nodes:
            continue  
        aux[node_type].append(node_id)


    # Remove p.fraction nodes from the selected nodes_type       
    for type, node_list in aux.items():
        # Calculate how many nodes we are going to remove
        k = round(len(node_list) * p.fraction)    

        # Remove the k random, distinct candidates (using the seed the rng to ensure seed reproducibility)
        nodes_to_remove = rng.sample(node_list,k)
        log(f"    Removing the following {type} nodes = {nodes_to_remove}")
        G.remove_nodes_from(nodes_to_remove)

    log("*"*50 +"\n")

    return G 


# =============================================================================
# 8. Operations: edges and time
# =============================================================================

def _remove_edges(G: nx.MultiDiGraph, mal_nodes: set[str], p, rng: random.Random) -> nx.Graph: 
    """
    Simulated log loss: removes a share of the candidate edges (one lost log line = one lost edge).

    Which edges can be lost is decided by _candidate_edges (p.target, p.edge_rule,
    p.edge_types); which of them are lost, by _select (p.selection, p.fraction).

    Args:
        G: Graph of one time window (networkx.MultiDiGraph).
        mal_nodes: IDs (str) of the malicious nodes present in G, e.g. {'147459', '355470'}.
        p: The perturbation parameters, cfg.transformation.mal_perturbation.
            Uses p.target, p.edge_rule, p.edge_types, p.selection, p.fraction
            (and p.important_event_types / p.ego_radius for some selections).
        rng: random.Random seeded with p.seed, used for every random choice.

    Returns:
        G, modified in place: the chosen edges are removed. Updates
        _STATS["candidate_edges"] and _STATS["removed_edges"].

    Example:
        With p.target="malicious", p.edge_rule="either_node", p.selection="random",
        p.fraction=0.5: a window with 40 edges touching malicious nodes loses 20 of them,
        chosen at random (always the same 20 for the same p.seed).
    """
    # 1. WHAT can be lost: the edges allowed by p.target / p.edge_rule / p.edge_types.
    #    This list is the denominator of X% (p.fraction is a share of it).
    candidates = _candidate_edges(G, mal_nodes, p)

    # 2. WHICH of them are lost: random, burst, or highest-scored, depending on p.selection.
    chosen = _select(G, candidates, p, rng, mal_nodes)

    # 3. Remove them. Each (u, v, key) identifies exactly one edge, so parallel edges
    #    between the same two nodes are removed one by one, not all together.
    #    Nodes left without edges stay in G, but the later stages ignore them.
    G.remove_edges_from(chosen)

    # 4. Bookkeeping for log_summary (actual_loss_rate = removed / candidates).
    _STATS["candidate_edges"] += len(candidates)
    _STATS["removed_edges"] += len(chosen)
    log(f"    remove_edges: {len(chosen)} of {len(candidates)} candidate edges removed"
        f" (e.g. {chosen[:3]})")
    return G

def _shift_time(G, mal_nodes, p, rng) -> nx.Graph:
    """TODO"""
    log(f"    Shifting time from malicious nodes with the folowing config:\n{p}")

    return G


# =============================================================================
# 9. Entry point
# =============================================================================

def main(G: nx.Graph, cfg) ->nx.Graph:
    """Returns a graphs with a selected pertubations applied"""
    nodes_before, edges_before = G.number_of_nodes(), G.number_of_edges()
    _STATS["windows_seen"] += 1 
    #log("Main function of mal_perturbation.py")
    log("=" * 50 + "\n")
    log(f"     type of graph: {type(G)}")
    log(f"     perturbing a graph with {nodes_before} nodes")
    log(f"     perturbing a graph with {edges_before} edges")
    p = cfg.transformation.mal_perturbation
    mal_nodes = _malicious_nodes_in_graph(G, cfg) 

    if p.target == "malicious" and not mal_nodes:
        return G  # nothing to lose in this window
    
    mal_before = set(mal_nodes)

    rng = random.Random(p.seed)

    if p.operation == "remove_neighbors" :
        nr_nodes = len(G.nodes)
        G = _remove_neighbors(G,mal_nodes,p,rng)
        log(f"     Original graph had [{nr_nodes}] nodes after removing neighbours it has [{len(G.nodes)}] nodes")
    elif p.operation == "remove_edges":
        G = _remove_edges(G, mal_nodes, p, rng)
    elif p.operation == "shift_time":
        G = _shift_time(G, mal_nodes, p, rng)
    elif p.operation == "remove_network_nodes":
        G = _remove_network_nodes(G, mal_nodes, p, rng)
    elif p.operation == "remove_subject_and_network":
        G = _remove_subject_and_network(G, mal_nodes, p, rng)
    elif p.operation == "remove_random_nodes":
        G = _remove_random_nodes(G, mal_nodes, p, rng) 
    else:
        log("Operation doesnt exist, returning unperturbed graph")
    #log(f"    {G.nodes(data=True)}")
    #log(f"    {G.edges(keys=True,data=True)}")
    #log(f"    {p.direction}")
    #log(f"    {p.edge_types}")
    #log(f"    {p.node_types}")
    #log(f"    {p.fraction}")
    #log(f"    {p.operation}")
    #log(f"    {p.seed}")
    #log(f"    {p.time_offset_s}")
    _record_stats(G, mal_before, nodes_before, edges_before, cfg)

    log("=" * 50 + "\n")
    return G


# =============================================================================
# 10. Statistics
# =============================================================================

def _record_stats(G: nx.MultiDiGraph, mal_before: set[str], nodes_before: int, edges_before: int, cfg) -> None:
    """
    Adds this window's counts to _STATS.
 
    Args:
        G: The graph after the perturbation.
        mal_before: set[str] of malicious nodes present before the perturbation.
        nodes_before: Number of nodes before the perturbation.
        edges_before: Number of edges before the perturbation.
        cfg: Full PIDSMaker config (the .yml config + command-line overrides), as
            built by get_yml_cfg. Must contain cfg.dataset and cfg.transformation.
 
    Returns:
        None. Updates windows_perturbed, nodes/edges before and after, and
        malicious_nodes_before/after (for coverage).
    """
    mal_after = {n for n in _malicious_nodes_in_graph(G, cfg) if G.degree(n) > 0}
    _STATS["windows_perturbed"] += 1
    _STATS["nodes_before"] += nodes_before
    _STATS["nodes_after"] += G.number_of_nodes()
    _STATS["edges_before"] += edges_before
    _STATS["edges_after"] += G.number_of_edges()
    _STATS["malicious_nodes_before"] += len(mal_before)
    _STATS["malicious_nodes_after"] += len(mal_after)

def log_summary():
    """Logs the totals for all test windows once, then resets them."""
    stats = dict(_STATS)
    stats["nodes_removed"] = stats.get("nodes_before", 0) - stats.get("nodes_after", 0)
    stats["edges_removed"] = stats.get("edges_before", 0) - stats.get("edges_after", 0)

    log(f"[mal_perturbation] summary: {stats}")
    wandb.log({f"perturbation/{k}": v for k, v in stats.items()})
    _STATS.clear()