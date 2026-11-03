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
    # Experiment config
    ('CADETS_E3', 'orthrus') : {
        'nids': [147459, 356868, 147460, 147461, 2446982, 2609543, 26254, 355470, 337550, 370961, 140956, 140957, 355357, 354975, 140960, 26277, 2444455, 354935, 26281, 337065, 381102, 355247, 355502, 355507, 2609587, 2609590, 141183, 355640, 355641, 370873, 2442683, 147515, 354877, 370874, 1219519, 211776, 370875, 370876, 354940, 355657, 26318, 355535, 370896, 370897, 370898, 2445651, 370899, 2446677, 418674, 370903, 336472, 370904, 379482, 141147, 336477, 2446308, 141285, 355176, 355439, 355056, 2445298, 379506, 355572, 26357, 228725, 355447, 380024, 355316, 354938, 2447478, 354933, 2442623], 
        'labels': {211776: "{'subject': 'None nginx'}", 26277: "{'netflow': '128.55.12.73:80->81.49.200.166:43530'}", 26281: "{'netflow': '128.55.12.73:38265->200.36.109.214:80'}", 26254: "{'netflow': '128.55.12.73:80->81.49.200.166:44623'}", 26318: "{'netflow': '128.55.12.73:19857->139.123.0.113:80'}", 26357: "{'netflow': '128.55.12.73:17330->61.167.39.128:80'}", 228725: "{'subject': 'None vUgefal'}", 1219519: "{'file': '/tmp/vUgefal'}", 2446982: "{'file': '/tmp/main'}", 355470: "{'subject': 'None main'}", 337550: "{'subject': 'None nginx'}", 140956: "{'netflow': '128.55.12.73:80->25.159.96.207:45203'}", 140957: "{'netflow': '128.55.12.73:46517->76.56.184.25:80'}", 355357: "{'subject': 'None XIM'}", 354975: "{'subject': 'None tmux-1002'}", 140960: "{'netflow': '128.55.12.73:12680->155.162.39.48:80'}", 2444455: "{'file': '/tmp/minions'}", 354935: "{'subject': 'None python2.7'}", 337065: "{'subject': 'None sendmail'}", 381102: "{'file': '/var/log/salt/minion'}", 355247: "{'subject': 'None minions'}", 355502: "{'subject': 'None sendmail'}", 355507: "{'subject': 'None sendmail'}", 141183: "{'netflow': '128.55.12.73:39242->53.158.101.118:80'}", 355641: "{'subject': 'None test'}", 2442683: "{'file': '/var/cache/salt/minion/proc/20180412180113291397'}", 354877: "{'subject': 'None top'}", 355657: "{'subject': 'None test'}", 355535: "{'subject': 'None test'}", 2445651: "{'file': '/tmp/XIM'}", 2446677: "{'file': '/var/log/sendmail'}", 336472: "{'subject': 'None python2.7'}", 379482: "{'file': 'None'}", 141147: "{'netflow': '128.55.12.73:60746->53.158.101.118:80'}", 336477: "{'subject': 'None sendmail'}", 2446308: "{'file': '/var/log/netlog'}", 141285: "{'netflow': '128.55.12.73:34345->192.113.144.28:80'}", 355176: "{'subject': 'None minions'}", 355439: "{'subject': 'None sendmail'}", 355056: "{'subject': 'None tmux-1002'}", 2445298: "{'file': '/tmp/font'}", 379506: "{'file': 'None'}", 355572: "{'subject': 'None test'}", 355316: "{'subject': 'None XIM'}", 2447478: "{'file': '/tmp/test'}", 355447: "{'subject': 'None sendmail'}", 380024: "{'file': '/dev/random'}", 354933: "{'subject': 'None python2.7'}", 354938: "{'subject': 'None sendmail'}", 354940: "{'subject': 'None sendmail'}", 2442623: "{'file': '/tmp/tmux-1002'}", 147459: "{'netflow': '128.55.12.73:80->25.159.96.207:58625'}", 147460: "{'netflow': '128.55.12.73:49722->76.56.184.25:80'}", 147461: "{'netflow': '128.55.12.73:27115->155.162.39.48:80'}", 356868: "{'subject': 'None nginx'}", 2609543: "{'file': '/tmp/pEja72mA'}", 370896: "{'subject': 'None sshd'}", 370961: "{'subject': 'None pEja72mA'}", 370897: "{'subject': 'None sshd'}", 370898: "{'subject': 'None sshd'}", 370899: "{'subject': 'None sshd'}", 370903: "{'subject': 'None mkdir'}", 370904: "{'subject': 'None wget'}", 147515: "{'netflow': '128.55.12.73:63341->53.158.101.118:80'}", 418674: "{'file': 'None'}", 2609587: "{'file': '/usr/home/user/eraseme'}", 2609590: "{'file': '/usr/home/user/eraseme/index.html'}", 355640: "{'subject': 'None sshd'}", 370873: "{'subject': 'None sshd'}", 370874: "{'subject': 'None sshd'}", 370875: "{'subject': 'None sshd'}", 370876: "{'subject': 'None sshd'}"}, 
        'uuid_to_nid': {'674D8313-390A-11E8-BF66-D9AA8AFF4A69': 211776, '60040266-39AE-11E8-BF66-D9AA8AFF4A69': 26277, '6034BA72-39AE-11E8-BF66-D9AA8AFF4A69': 26281, 'FFF277E0-39AD-11E8-BF66-D9AA8AFF4A69': 26254, 'D384652A-39AF-11E8-BF66-D9AA8AFF4A69': 26318, '323ED9A0-39B1-11E8-BF66-D9AA8AFF4A69': 26357, 'D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69': 228725, 'F77E454D-CA07-6B5D-87CA-9EFDCD6BA3ED': 1219519, '4DA445A7-56DB-D353-9B56-AD9CD3D373D6': 2446982, '5CD609A7-3E7F-11E8-A5CB-3FA3753A265A': 355470, '11C64B2C-3DC3-11E8-A5CA-3FA3753A265A': 337550, '5EE4F8FC-3E7B-11E8-A5CB-3FA3753A265A': 140956, '5EE54774-3E7B-11E8-A5CB-3FA3753A265A': 140957, '48289024-3E7E-11E8-A5CB-3FA3753A265A': 355357, 'C4F4FF22-3E7B-11E8-A5CB-3FA3753A265A': 354975, '5F12229C-3E7B-11E8-A5CB-3FA3753A265A': 140960, '74D78344-4A18-265B-984A-8D22BB26DDCF': 2444455, '7CF2DDA4-3E7B-11E8-A5CB-3FA3753A265A': 354935, '1AC05B7A-3DC3-11E8-A5CB-3FA3753A265A': 337065, '1902FFA3-6F80-2052-806F-3D6A2220819E': 381102, '7B30E76D-3E7D-11E8-A5CB-3FA3753A265A': 355247, 'AE11D308-3E7F-11E8-A5CB-3FA3753A265A': 355502, 'B2C5B97D-3E7F-11E8-A5CB-3FA3753A265A': 355507, '482AD2B6-3E7E-11E8-A5CB-3FA3753A265A': 141183, '327621AE-3E80-11E8-A5CB-3FA3753A265A': 355641, '60EBF436-633F-B75F-BF63-A8040FB73989': 2442683, '34612C08-3E7B-11E8-A5CB-3FA3753A265A': 354877, '47E61FFC-3E80-11E8-A5CB-3FA3753A265A': 355657, 'DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A': 355535, '5026C48F-56BA-3E5B-BA56-DD382B3EC82B': 2445651, 'CBBF8038-5237-8651-B752-A1C99186128A': 2446677, '1131CD42-3DC3-11E8-A5CA-3FA3753A265A': 336472, '51110606-D232-9652-B2D2-3A7242968F8A': 379482, '21A20E29-3E7E-11E8-A5CB-3FA3753A265A': 141147, '15FD3B4A-3DC3-11E8-A5CB-3FA3753A265A': 336477, 'E5F1BC5B-052D-3F5F-AD05-928A8F3FF746': 2446308, '47EA0B5C-3E80-11E8-A5CB-3FA3753A265A': 141285, '17C4C0C3-3E7D-11E8-A5CB-3FA3753A265A': 355176, '15267234-3E7F-11E8-A5CB-3FA3753A265A': 355439, '42E4A848-3E7C-11E8-A5CB-3FA3753A265A': 355056, 'F993C224-C6AD-AB5C-ADC6-09316CABFFD8': 2445298, '1633500B-D34B-8058-8BD3-ABB7D880915E': 379506, '0001A528-3E80-11E8-A5CB-3FA3753A265A': 355572, '219DE547-3E7E-11E8-A5CB-3FA3753A265A': 355316, '84D440C2-4E50-4A5C-904E-C4772C4ACD5A': 2447478, '1D3ACF79-3E7F-11E8-A5CB-3FA3753A265A': 355447, '416AB837-8E42-6D58-828E-6976586D8E68': 380024, '7CED5514-3E7B-11E8-A5CB-3FA3753A265A': 354933, '7D2E10B3-3E7B-11E8-A5CB-3FA3753A265A': 354938, '81E2003D-3E7B-11E8-A5CB-3FA3753A265A': 354940, '5453C813-1A0E-4359-8E1A-41B40943CDC5': 2442623, '937BA111-3F1B-11E8-A5CB-3FA3753A265A': 147459, '937BE863-3F1B-11E8-A5CB-3FA3753A265A': 147460, '93A2D6AC-3F1B-11E8-A5CB-3FA3753A265A': 147461, '11C65665-3DC3-11E8-A5CA-3FA3753A265A': 356868, 'E5A15412-68E0-FD54-A068-DD6114FD9040': 2609543, '042ADADF-3F1C-11E8-A5CB-3FA3753A265A': 370896, '4FB0BFEA-3F1C-11E8-A5CB-3FA3753A265A': 370961, '0433BCDC-3F1C-11E8-A5CB-3FA3753A265A': 370897, '044B097A-3F1C-11E8-A5CB-3FA3753A265A': 370898, '04632D66-3F1C-11E8-A5CB-3FA3753A265A': 370899, '0488BCD7-3F1C-11E8-A5CB-3FA3753A265A': 370903, '04A9D03C-3F1C-11E8-A5CB-3FA3753A265A': 370904, '4FB30E44-3F1C-11E8-A5CB-3FA3753A265A': 147515, '3209A26F-A6EF-0350-AFA6-B1BD1003D390': 418674, 'EC6F1E3C-792F-485D-AF79-1A832D489243': 2609587, '00C8E4E5-8BBC-D45B-BC8B-D32BABD4AFCE': 2609590, '2CA83801-3E80-11E8-A5CB-3FA3753A265A': 355640, 'E0C1A46B-3F1B-11E8-A5CB-3FA3753A265A': 370873, 'E0CAAC23-3F1B-11E8-A5CB-3FA3753A265A': 370874, 'E0E17EDD-3F1B-11E8-A5CB-3FA3753A265A': 370875, 'E0F82A6C-3F1B-11E8-A5CB-3FA3753A265A': 370876}
    }
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
        An object with the following keys:
            * "nids" : the set of malicious node IDs, the integer IDs used for nodes in the graphs 
            * "lables" : a dictionary from each malicious node ID to its label in the ground-truth file (a process name, file path or IP address).
            * "uuid_to_nid" : a dictionary from each malicious nodes original database UUID to its node ID.

    """
    key = (cfg.dataset.name, cfg.evaluation.ground_truth_version)
    if key not in _CACHE:
        gt_nids, gt_labels, uuid_to_nid = get_ground_truth(cfg)
        _CACHE[key] = { 
            "nids" : [int(n) for n in gt_nids],
            "labels" : {int(n): label for n, label in gt_labels.items()},
            "uuid_to_nid": {uuid: int(n) for uuid, n in uuid_to_nid.items()}
        }
        log(f"[mal_pertubation] loaded {len(_CACHE[key]['nids'])} malicious node IDs for {key}")
    return _CACHE[key]



def dates_to_perturb(cfg) -> list[str]:
    """
    Returns the dates whose graphs must be perturbed, according to p.split.
 
    "train"     -> cfg.dataset.train_dates
    "val"       -> cfg.dataset.val_dates
    "train_val" -> train_dates + val_dates
    "test"      -> cfg.dataset.test_dates
 
    Called once by transformation.py, before its loop, instead of using test_dates directly.
    Raises ValueError for an unknown split.
    """

    raise NotImplementedError


def _malicious_nodes_in_graph(G: nx.MultiDiGraph, cfg) -> set[str]:
    """Returns the IDs (as strings, like the graph) of the ground-truth nodes present in G."""
    raise NotImplementedError


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
    """Says whether edge u -> v counts as malicious under p.edge_rule:

    "src_node"    -> u is malicious
    "dst_node"    -> v is malicious
    "both_nodes"  -> u and v are malicious   (the attack chain itself)
    "either_node" -> u or v is malicious
    """
    raise NotImplementedError


def _matches_edge_types(data: dict, edge_types: str) -> bool:
    """True if the edge's "label" is in p.edge_types (comma-separated), or if edge_types
    is empty (meaning: all types)."""
    raise NotImplementedError


def _candidate_edges(G: nx.MultiDiGraph, mal_nodes: set[str], p) -> list[tuple]:
    """Returns the edges that may be lost, as (u, v, k) tuples, according to p.target:

    "malicious" -> edges that _is_malicious_edge accepts (testing side)
    "benign"    -> edges touching no malicious node at all (training side)
    "all"       -> every edge (realistic loss: benign and malicious alike)

    Also applies the p.edge_types filter.
    This set is the denominator of X%: fraction is a share of these candidates.
    """
    raise NotImplementedError


# =============================================================================
# 5. Selection (WHICH candidates are lost)
# =============================================================================

def _select(G: nx.MultiDiGraph, candidates: list[tuple], p, rng: random.Random) -> list[tuple]:
    """Dispatches on p.selection and returns the edges to remove:

    "random"                                           -> _select_random
    "burst"                                            -> _select_burst
    "degree" / "betweenness" / "event_type" / "rarity" -> _select_top_scored with the
                                                          matching scoring function
    Raises ValueError for an unknown selection.
    """
    raise NotImplementedError


def _num_to_remove(n_candidates: int, fraction: float) -> int:
    """k = round(n_candidates * fraction), kept between 0 and n_candidates."""
    raise NotImplementedError


def _select_random(candidates: list[tuple], fraction: float, rng: random.Random) -> list[tuple]:
    """Realistic loss: k random candidates. Sort the candidates first so the same seed
    always gives the same result, then rng.sample."""
    raise NotImplementedError


def _select_burst(
    G: nx.MultiDiGraph, candidates: list[tuple], fraction: float, rng: random.Random
) -> list[tuple]:
    """Capture outage: picks one random time interval covering `fraction` of the window's
    duration (min to max edge time in G) and returns the candidates whose "time" falls
    inside it. The number removed is therefore approximately, not exactly, k."""
    raise NotImplementedError


def _select_top_scored(
    G: nx.MultiDiGraph, candidates: list[tuple], fraction: float, score_fn, p
) -> list[tuple]:
    """Worst-case loss: scores every candidate with score_fn(G, edge, p), sorts by score
    (highest first, ties broken by the edge itself so the order is fixed) and returns
    the top k."""
    raise NotImplementedError


# =============================================================================
# 6. Importance scores (used by _select_top_scored); higher = more important
# =============================================================================

def _score_degree(G: nx.MultiDiGraph, edge: tuple, p) -> float:
    """Structural: importance of the edge's endpoints, e.g. degree(u) + degree(v).
    Tip: compute the degrees once per graph, not once per edge."""
    raise NotImplementedError


def _score_betweenness(G: nx.MultiDiGraph, edge: tuple, p) -> float:
    """Structural: edge betweenness, computed on a simplified copy (nx.Graph(G)) of the
    ego graph around the malicious nodes (radius p.ego_radius), since full betweenness
    is slow on large windows. Compute once per graph and look the edge up."""
    raise NotImplementedError


def _score_event_type(G: nx.MultiDiGraph, edge: tuple, p) -> float:
    """Attack semantics: high score if the edge's "label" is in p.important_event_types
    (e.g. EVENT_EXECUTE, EVENT_CONNECT, EVENT_WRITE), low otherwise. You may give each
    listed type its own weight (e.g. by its position in the list)."""
    raise NotImplementedError


def _score_rarity(G: nx.MultiDiGraph, edge: tuple, p) -> float:
    """Anomaly-relevant: rare things score high, e.g. 1 / count of this
    (src node_type, event type, dst node_type) combination in the window."""
    raise NotImplementedError


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
        TODO: this doenst affect the final model, because the model only trains on normal data
        and learns to reconstruct it, so tampering with the malicious nodes, used for testing
        , doesnt affect the final model (this function must be adapted to remove neighours of 
        normal nodes, not malicous ones)
        
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

def _remove_edges(G, mal_nodes, p, rng) -> nx.Graph: 
    """TODO
    --transformation.mal_perturbation.direction=[in,out,both] 
    --edge_types=[...] 
    --transformation.mal_perturbation.fraction=0.5
    --transformation.mal_perturbation.seed=42 

    Planned (log-loss experiments, both sides; one lost log line = one lost edge):
    candidates = _candidate_edges(...), chosen = _select(...), G.remove_edges_from(chosen).
    Records the number of candidates and of removed edges in _STATS. Returns G.
    """
    log("*"*50 +"\n")
    log(f"    Removing edges from malicious nodes with the folowing config:\n{p}")
    mal_edges = _incident_edges(G, mal_nodes, p.direction)
    mal_in_edges = mal_edges['inbound_edges']
    mal_out_edges = mal_edges['outbound_edges']

    # TODO: verificar config a ver se edge_types pedidas existem na definição original (não so no grafo atual)
    # caso edge_type não existe nos nos maliciosos returnar o grafo logo 

    candidate_in_edges = []
    log(f"    In edges {type(mal_in_edges)} : {mal_in_edges}")

    # Get candidate inbound edges
    for edge in mal_in_edges:
        log(edge)

    # Get candidate outbound edges

    
    candidate_out_edges = []
    log(f"    Out edges {type(mal_out_edges)} : {mal_out_edges}")
    log("*"*50 +"\n")
    return G 

def _shift_time(G, mal_nodes, p, rng) -> nx.Graph:
    """TODO"""
    log(f"    Shifting time from malicious nodes with the folowing config:\n{p}")

    return G


# Name -> function for every operation. Not used by main() yet (main uses its if/elif
# chain); it can replace that chain later: G = OPERATIONS[p.operation](G, mal_nodes, p, rng)
OPERATIONS = {
    "remove_neighbors": _remove_neighbors,
    "remove_edges": _remove_edges,
    "shift_time": _shift_time,
    "remove_network_nodes": _remove_network_nodes,
    "remove_subject_and_network": _remove_subject_and_network,
    "remove_random_nodes": _remove_random_nodes,
}


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
    mal_nodes_details = _malicious_ids(cfg)
    mal_nodes = [str(n) for n in mal_nodes_details['nids']]

    if not mal_nodes:                                    
        return G

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
    _STATS["malicious_nodes_seen"] += len(mal_nodes)
    _STATS["nodes_before"] += nodes_before
    _STATS["nodes_after"] += G.number_of_nodes()
    _STATS["edges_before"] += edges_before
    _STATS["edges_after"] += G.number_of_edges()
    log("=" * 50 + "\n")
    return G


# =============================================================================
# 10. Statistics
# =============================================================================

def _record_stats(G: nx.MultiDiGraph, mal_before: set[str], nodes_before: int, edges_before: int, cfg) -> None:
    """Adds this window's numbers to _STATS:
    windows_perturbed, nodes/edges before and after, and for the testing side
    the coverage figures: malicious nodes present before and after (a malicious node
    that lost all its edges is no longer present and cannot be detected).
    Can later replace the _STATS lines at the end of main()."""
    raise NotImplementedError


def log_summary():
    """Logs the totals for all test windows once, then resets them."""
    stats = dict(_STATS)
    stats["nodes_removed"] = stats.get("nodes_before", 0) - stats.get("nodes_after", 0)
    stats["edges_removed"] = stats.get("edges_before", 0) - stats.get("edges_after", 0)

    log(f"[mal_perturbation] summary: {stats}")
    wandb.log({f"perturbation/{k}": v for k, v in stats.items()})
    _STATS.clear()