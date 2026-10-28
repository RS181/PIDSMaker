import random
import networkx as nx
from pidsmaker.utils.utils import log
from pidsmaker.utils.labelling import get_ground_truth

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


_CACHE = {
    # Experiment config
    ('CADETS_E3', 'orthrus') : {
        'nids': [147459, 356868, 147460, 147461, 2446982, 2609543, 26254, 355470, 337550, 370961, 140956, 140957, 355357, 354975, 140960, 26277, 2444455, 354935, 26281, 337065, 381102, 355247, 355502, 355507, 2609587, 2609590, 141183, 355640, 355641, 370873, 2442683, 147515, 354877, 370874, 1219519, 211776, 370875, 370876, 354940, 355657, 26318, 355535, 370896, 370897, 370898, 2445651, 370899, 2446677, 418674, 370903, 336472, 370904, 379482, 141147, 336477, 2446308, 141285, 355176, 355439, 355056, 2445298, 379506, 355572, 26357, 228725, 355447, 380024, 355316, 354938, 2447478, 354933, 2442623], 
        'labels': {211776: "{'subject': 'None nginx'}", 26277: "{'netflow': '128.55.12.73:80->81.49.200.166:43530'}", 26281: "{'netflow': '128.55.12.73:38265->200.36.109.214:80'}", 26254: "{'netflow': '128.55.12.73:80->81.49.200.166:44623'}", 26318: "{'netflow': '128.55.12.73:19857->139.123.0.113:80'}", 26357: "{'netflow': '128.55.12.73:17330->61.167.39.128:80'}", 228725: "{'subject': 'None vUgefal'}", 1219519: "{'file': '/tmp/vUgefal'}", 2446982: "{'file': '/tmp/main'}", 355470: "{'subject': 'None main'}", 337550: "{'subject': 'None nginx'}", 140956: "{'netflow': '128.55.12.73:80->25.159.96.207:45203'}", 140957: "{'netflow': '128.55.12.73:46517->76.56.184.25:80'}", 355357: "{'subject': 'None XIM'}", 354975: "{'subject': 'None tmux-1002'}", 140960: "{'netflow': '128.55.12.73:12680->155.162.39.48:80'}", 2444455: "{'file': '/tmp/minions'}", 354935: "{'subject': 'None python2.7'}", 337065: "{'subject': 'None sendmail'}", 381102: "{'file': '/var/log/salt/minion'}", 355247: "{'subject': 'None minions'}", 355502: "{'subject': 'None sendmail'}", 355507: "{'subject': 'None sendmail'}", 141183: "{'netflow': '128.55.12.73:39242->53.158.101.118:80'}", 355641: "{'subject': 'None test'}", 2442683: "{'file': '/var/cache/salt/minion/proc/20180412180113291397'}", 354877: "{'subject': 'None top'}", 355657: "{'subject': 'None test'}", 355535: "{'subject': 'None test'}", 2445651: "{'file': '/tmp/XIM'}", 2446677: "{'file': '/var/log/sendmail'}", 336472: "{'subject': 'None python2.7'}", 379482: "{'file': 'None'}", 141147: "{'netflow': '128.55.12.73:60746->53.158.101.118:80'}", 336477: "{'subject': 'None sendmail'}", 2446308: "{'file': '/var/log/netlog'}", 141285: "{'netflow': '128.55.12.73:34345->192.113.144.28:80'}", 355176: "{'subject': 'None minions'}", 355439: "{'subject': 'None sendmail'}", 355056: "{'subject': 'None tmux-1002'}", 2445298: "{'file': '/tmp/font'}", 379506: "{'file': 'None'}", 355572: "{'subject': 'None test'}", 355316: "{'subject': 'None XIM'}", 2447478: "{'file': '/tmp/test'}", 355447: "{'subject': 'None sendmail'}", 380024: "{'file': '/dev/random'}", 354933: "{'subject': 'None python2.7'}", 354938: "{'subject': 'None sendmail'}", 354940: "{'subject': 'None sendmail'}", 2442623: "{'file': '/tmp/tmux-1002'}", 147459: "{'netflow': '128.55.12.73:80->25.159.96.207:58625'}", 147460: "{'netflow': '128.55.12.73:49722->76.56.184.25:80'}", 147461: "{'netflow': '128.55.12.73:27115->155.162.39.48:80'}", 356868: "{'subject': 'None nginx'}", 2609543: "{'file': '/tmp/pEja72mA'}", 370896: "{'subject': 'None sshd'}", 370961: "{'subject': 'None pEja72mA'}", 370897: "{'subject': 'None sshd'}", 370898: "{'subject': 'None sshd'}", 370899: "{'subject': 'None sshd'}", 370903: "{'subject': 'None mkdir'}", 370904: "{'subject': 'None wget'}", 147515: "{'netflow': '128.55.12.73:63341->53.158.101.118:80'}", 418674: "{'file': 'None'}", 2609587: "{'file': '/usr/home/user/eraseme'}", 2609590: "{'file': '/usr/home/user/eraseme/index.html'}", 355640: "{'subject': 'None sshd'}", 370873: "{'subject': 'None sshd'}", 370874: "{'subject': 'None sshd'}", 370875: "{'subject': 'None sshd'}", 370876: "{'subject': 'None sshd'}"}, 
        'uuid_to_nid': {'674D8313-390A-11E8-BF66-D9AA8AFF4A69': 211776, '60040266-39AE-11E8-BF66-D9AA8AFF4A69': 26277, '6034BA72-39AE-11E8-BF66-D9AA8AFF4A69': 26281, 'FFF277E0-39AD-11E8-BF66-D9AA8AFF4A69': 26254, 'D384652A-39AF-11E8-BF66-D9AA8AFF4A69': 26318, '323ED9A0-39B1-11E8-BF66-D9AA8AFF4A69': 26357, 'D3822AFC-39AF-11E8-BF66-D9AA8AFF4A69': 228725, 'F77E454D-CA07-6B5D-87CA-9EFDCD6BA3ED': 1219519, '4DA445A7-56DB-D353-9B56-AD9CD3D373D6': 2446982, '5CD609A7-3E7F-11E8-A5CB-3FA3753A265A': 355470, '11C64B2C-3DC3-11E8-A5CA-3FA3753A265A': 337550, '5EE4F8FC-3E7B-11E8-A5CB-3FA3753A265A': 140956, '5EE54774-3E7B-11E8-A5CB-3FA3753A265A': 140957, '48289024-3E7E-11E8-A5CB-3FA3753A265A': 355357, 'C4F4FF22-3E7B-11E8-A5CB-3FA3753A265A': 354975, '5F12229C-3E7B-11E8-A5CB-3FA3753A265A': 140960, '74D78344-4A18-265B-984A-8D22BB26DDCF': 2444455, '7CF2DDA4-3E7B-11E8-A5CB-3FA3753A265A': 354935, '1AC05B7A-3DC3-11E8-A5CB-3FA3753A265A': 337065, '1902FFA3-6F80-2052-806F-3D6A2220819E': 381102, '7B30E76D-3E7D-11E8-A5CB-3FA3753A265A': 355247, 'AE11D308-3E7F-11E8-A5CB-3FA3753A265A': 355502, 'B2C5B97D-3E7F-11E8-A5CB-3FA3753A265A': 355507, '482AD2B6-3E7E-11E8-A5CB-3FA3753A265A': 141183, '327621AE-3E80-11E8-A5CB-3FA3753A265A': 355641, '60EBF436-633F-B75F-BF63-A8040FB73989': 2442683, '34612C08-3E7B-11E8-A5CB-3FA3753A265A': 354877, '47E61FFC-3E80-11E8-A5CB-3FA3753A265A': 355657, 'DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A': 355535, '5026C48F-56BA-3E5B-BA56-DD382B3EC82B': 2445651, 'CBBF8038-5237-8651-B752-A1C99186128A': 2446677, '1131CD42-3DC3-11E8-A5CA-3FA3753A265A': 336472, '51110606-D232-9652-B2D2-3A7242968F8A': 379482, '21A20E29-3E7E-11E8-A5CB-3FA3753A265A': 141147, '15FD3B4A-3DC3-11E8-A5CB-3FA3753A265A': 336477, 'E5F1BC5B-052D-3F5F-AD05-928A8F3FF746': 2446308, '47EA0B5C-3E80-11E8-A5CB-3FA3753A265A': 141285, '17C4C0C3-3E7D-11E8-A5CB-3FA3753A265A': 355176, '15267234-3E7F-11E8-A5CB-3FA3753A265A': 355439, '42E4A848-3E7C-11E8-A5CB-3FA3753A265A': 355056, 'F993C224-C6AD-AB5C-ADC6-09316CABFFD8': 2445298, '1633500B-D34B-8058-8BD3-ABB7D880915E': 379506, '0001A528-3E80-11E8-A5CB-3FA3753A265A': 355572, '219DE547-3E7E-11E8-A5CB-3FA3753A265A': 355316, '84D440C2-4E50-4A5C-904E-C4772C4ACD5A': 2447478, '1D3ACF79-3E7F-11E8-A5CB-3FA3753A265A': 355447, '416AB837-8E42-6D58-828E-6976586D8E68': 380024, '7CED5514-3E7B-11E8-A5CB-3FA3753A265A': 354933, '7D2E10B3-3E7B-11E8-A5CB-3FA3753A265A': 354938, '81E2003D-3E7B-11E8-A5CB-3FA3753A265A': 354940, '5453C813-1A0E-4359-8E1A-41B40943CDC5': 2442623, '937BA111-3F1B-11E8-A5CB-3FA3753A265A': 147459, '937BE863-3F1B-11E8-A5CB-3FA3753A265A': 147460, '93A2D6AC-3F1B-11E8-A5CB-3FA3753A265A': 147461, '11C65665-3DC3-11E8-A5CA-3FA3753A265A': 356868, 'E5A15412-68E0-FD54-A068-DD6114FD9040': 2609543, '042ADADF-3F1C-11E8-A5CB-3FA3753A265A': 370896, '4FB0BFEA-3F1C-11E8-A5CB-3FA3753A265A': 370961, '0433BCDC-3F1C-11E8-A5CB-3FA3753A265A': 370897, '044B097A-3F1C-11E8-A5CB-3FA3753A265A': 370898, '04632D66-3F1C-11E8-A5CB-3FA3753A265A': 370899, '0488BCD7-3F1C-11E8-A5CB-3FA3753A265A': 370903, '04A9D03C-3F1C-11E8-A5CB-3FA3753A265A': 370904, '4FB30E44-3F1C-11E8-A5CB-3FA3753A265A': 147515, '3209A26F-A6EF-0350-AFA6-B1BD1003D390': 418674, 'EC6F1E3C-792F-485D-AF79-1A832D489243': 2609587, '00C8E4E5-8BBC-D45B-BC8B-D32BABD4AFCE': 2609590, '2CA83801-3E80-11E8-A5CB-3FA3753A265A': 355640, 'E0C1A46B-3F1B-11E8-A5CB-3FA3753A265A': 370873, 'E0CAAC23-3F1B-11E8-A5CB-3FA3753A265A': 370874, 'E0E17EDD-3F1B-11E8-A5CB-3FA3753A265A': 370875, 'E0F82A6C-3F1B-11E8-A5CB-3FA3753A265A': 370876}
    }
}

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
        print(f"[mal_pertubation] loaded {len(_CACHE[key]['nids'])} malicious node IDs for {key}")
    return _CACHE[key]

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
    print(f"    Finding {dir} edges that are touching malicous nodes: {mal_nodes}")
    in_edges = []
    out_edges =[]

    if(dir=="in" or dir=="all"):
        in_edges = G.in_edges(mal_nodes, keys=True, data=True)
    if(dir=="out" or dir=="all"):
        out_edges = G.out_edges(mal_nodes, keys=True, data=True)

    print(f"    Total Incoming edges: {len(in_edges)}")
    print(f"    Total Outgoing edges: {len(out_edges)}")

    return { "inbound_edges" : in_edges , "outbound_edges" : out_edges}


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
    print("*"*50 +"\n")
    print(f"    Removing malicious nodes neigbors (i.e. sucessors ) with the folowing config:\n{p}")
    candidate_neighbours = set()
    # Get candidate neigbours ids
    for node_id in mal_nodes:
        try:
            # print(f"Malicious Node with id [{node_id}] has attrs = {G.nodes[str(node_id)]}")
            for neighbor in G.neighbors(node_id):
                if neighbor not in mal_nodes:
                    candidate_neighbours.add(neighbor)
        except Exception as e:
            continue 
    
    if len(candidate_neighbours) == 0:
        print("*"*50 +"\n")
        return G
    
    # Sort list, so that the same seed always starts from the same order
    print(f"    Total number of candidate neighbours : {len(candidate_neighbours)}")
    print(f"    Ids of candidate neighbours : {candidate_neighbours}")
    s_candidate_neighbours = sorted(candidate_neighbours)

    # Calculate how many nodes we are going to remove
    k = round(len(s_candidate_neighbours) * p.fraction)

    # Remove the k random, distinct candidates (using the seed the rng to ensure seed reproducibility)
    neighbor_to_remove = rng.sample(s_candidate_neighbours,k)
    print(f"    Removing the following candidate neighbours = {neighbor_to_remove}")
    G.remove_nodes_from(neighbor_to_remove)
    print("*"*50 +"\n")

    return G



def _remove_edges(G, mal_nodes, p, rng) -> nx.Graph: 
    """TODO"""
    print(f"    Removing edges from malicious nodes with the folowing config:\n{p}")
    mal_edges = _incident_edges(G, mal_nodes, p.direction)
    mal_in_edges = mal_edges['inbound_edges']
    mal_out_edges = mal_edges['outbound_edges']


def _shift_time(G, mal_nodes, p, rng) -> nx.Graph:
    """TODO"""
    print(f"    Shifting time from malicious nodes with the folowing config:\n{p}")


def main(G: nx.Graph, cfg) ->nx.Graph:
    """Returns a graphs with a selected pertubations applied"""
    #log("Main function of mal_perturbation.py")
    print("=" * 50 + "\n")
    print(f"     type of graph: {type(G)}")
    print(f"     perturbing a graph with {G.number_of_nodes()} nodes")
    print(f"     perturbing a graph with {G.number_of_edges()} nodes")

    p = cfg.transformation.mal_perturbation
    
    mal_nodes_details = _malicious_ids(cfg)
    mal_nodes = [str(n) for n in mal_nodes_details['nids']]
    rng = random.Random(p.seed)

    if p.operation == "remove_neighbors" :
        nr_nodes = len(G.nodes)
        G = _remove_neighbors(G,mal_nodes,p,rng)
        print(f"     Original graph had [{nr_nodes}] nodes after removing neighbours it has [{len(G.nodes)}] nodes")
    elif p.operation == "remove_edges":
        G = _remove_edges(G, mal_nodes, p, rng)
    elif p.operation == "shift_time":
        G = _shift_time(G, mal_nodes, p, rng)
    else:
        print("Operation doesnt exist, returning unperturbed graph")
    



    #print(f"    {G.nodes(data=True)}")
    #print(f"    {G.edges(keys=True,data=True)}")
    #print(f"    {p.direction}")
    #print(f"    {p.edge_types}")
    #print(f"    {p.fraction}")
    #print(f"    {p.operation}")
    #print(f"    {p.seed}")
    #print(f"    {p.time_offset_s}")
    print("=" * 50 + "\n")

    return G
