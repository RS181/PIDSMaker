import argparse
import os
import sys
import re

SPLIT_VALS     = ["train","val","train_val","test"]
TARGET_VALS    = ["benign", "malicious", "all"]
SELECTION_VALS = ["random", "burst", "degree","betweenness", "event_type", "rarity"]
EDGE_RULE_VALS = ["src_node", "dst_node","both_nodes", "either_node"]
FRACTIONS_VALS = [0.1, 0.3, 0.5, 0.7, 0.9]

LOG_FOLDER = "./perturbation_tests/logs"

# Metric that are obtained from log files 
RESULT_DICT = {
    "run_args" : [],
    "precision" : [],
    "recall": [],
    "fpr" : [],
    "fscore" : [],
    "ap" : [],
    "accuracy" : [],
    "balanced_acc" : [],
    "auc" : [],
    "lr" : [],
    "dor" : [],
    "mcc" : [],
    "tp" : [],
    "fp" : [],
    "tn" : [],
    "fn" : [],
    "precision" : [],
    "recall" : [],
    "ap" : [],
    "precision" : [],
    "recall" : [],
    "ap" : [],
    "precision" : [],
    "recall" : [],
    "ap" : [],
    "fp_in_malicious_tw_ratio" : [],
    "percent_detected_attacks" : [],
    "fps_if_all_attacks_detected" : [],
    "tps_if_all_attacks_detected" : [],
    "precision_if_all_attacks_detected" : [],
    "recall_if_all_attacks_detected" : [],
    "adp_score" : [],
    "threshold" : [],
    "discrim_score_att_0" : [],
    "discrim_score_att_1" : [],
    "discrim_score_att_2" : [],
    "discrimination" : [],
    "discrim_tp_att_0" : [],
    "discrim_tp_att_1" : [],
    "discrim_tp_att_2" : [],
    "discrim_tp_att_sum" : [],
    "tp_att_0" : [],
    "tp_att_1" : [],
    "tp_att_2" : [],
    "epoch" : [],
    "nodes_total" : [],
    "nodes_malicious" : [],
    "nodes_benign" : [],
    "malicious_detected" : [],
    "malicious_undetected" : []
}



def check_logs(dataset: str, model: str) -> bool:
    """
    Check if there are any available runs, for the given
    model + dataset combination
    """
    path = f"{LOG_FOLDER}/{model}-{dataset}"    
    return os.path.exists(path) 



def clean_args(args):
    """
    Returns a dictionary with arguments that have 
    values (a.k.a are not None)
    """
    ans = {}
    for arg, v in vars(args).items():
        if v is not None:
            ans[arg] = v

    return ans


def filtrate_runs(args, runs: [str]) -> [str]:
    """
    Returns a list of runs that have the
    correct arguments. Check if first line 
    (wich list the perturbation keys and values)
    contains the values in args (it doesnt check key
    it only check values, so it is important that
    the values of each pertubation be diferent)
    """
    filtrated_runs = []
    exclude_keys = {'dataset', 'model'}
    filtrate_vals = [val for key, val in args.items() if key not in exclude_keys]

    for log_file in runs:
        skip = False
        with open(f"{LOG_FOLDER}/{args['model']}-{args['dataset']}/{log_file}") as f:
            # First line contains yyyy-mm-dd hh:mm:ss so 20: ignores those characters 
            first_line = f.readline()[20:]
            for filter in filtrate_vals:
                if filter not in first_line:
                    skip = True

            if not skip:
                filtrated_runs.append(log_file)

    print(f"Filtrated {len(filtrated_runs)} from a total of {len(runs)}")
    print(f"Filtrated using the following values  (not the keys):  {filtrate_vals} ")
    return filtrated_runs

def get_and_store_results(args, run : str):
    """
    Stores in RESULT_DICT the results of the best epoch, saved in the log files.
    This results were obtained agains the test set.
    """
    log_file_path = f"{LOG_FOLDER}/{args['model']}-{args['dataset']}/{run}"
    start_pattern = re.compile(r"Best epoch \((\d+)\) stats")
    stop_pattern = "Best scores file"
    collecting = False

    with open(log_file_path, 'r') as file:
        for line in file:

            if not collecting:
                match = start_pattern.search(line)
                if match:
                    collecting = True
                    continue  

            if collecting:
                # Check if this line is the stop condition
                if stop_pattern in line:
                    break
                # Process or save the line using your slice logic
                cleaned_line = line[21:].strip().split()
                key = cleaned_line[0].replace(":","")
                if key in RESULT_DICT:
                    val = cleaned_line[1]
                    RESULT_DICT[key].append(val)
                
def get_and_store_args(args, run : str):
    """
    Stores the arguments used in a run in RESULT_DICT
    """
    log_file_path = f"{LOG_FOLDER}/{args['model']}-{args['dataset']}/{run}"
    with open(log_file_path) as f:
        first_line = f.readline()[21:]
        RESULT_DICT["run_args"].append(first_line)


def summarize_runs(args):
    """
    Summarizes all .logs from a given:
    - dataset + model combination
    - filters given in args
    """
    args = clean_args(args)
    print(f"Filters (values) that are going to be applied : {args}")

    runs = os.listdir(f"{LOG_FOLDER}/{args['model']}-{args['dataset']}")
    filtered_runs = filtrate_runs(args,runs)

    if len(filtered_runs) == 0:
        print(f"No available runs after aplying given values in filter")
        sys,exit(0)


    for run in filtered_runs:
        if ".log" in run:
            get_and_store_args(args,run)
            get_and_store_results(args, run)

    print(RESULT_DICT)
    # TODO: arranjar forma de fazer print bonito
    # dos resultados

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=str, required=True, help="Choose the dataset")
    parser.add_argument("--model", type=str, required=True, help="Choose the model")
    parser.add_argument("--split", type=str, choices=SPLIT_VALS, help="Choose the split that the perturbations were applied")   
    parser.add_argument("--target", type=str, choices=TARGET_VALS, help="Choose the edges that were lost")   
    parser.add_argument("--selection", type=str, choices=SELECTION_VALS, help="Choose edge selection strategy used")
    parser.add_argument("--edge_rule", type=str, choices=EDGE_RULE_VALS, help="Choose wich edges counted as malicious (target=malicious)")
    parser.add_argument("--edge_type", type=str, help="Choose wich edges types were pertubed, empty=all")
    parser.add_argument("--fraction", type=str, choices=FRACTIONS_VALS, help="Choose wich edges types were pertubed, empty=all")
    parser.add_argument("--seed", type=str,  help="Choose wich seed was used, empty=all")

    args = parser.parse_args()

    if not check_logs(args.dataset, args.model):
        print(f"No run found for the dataset {args.dataset} and model {args.model} ")
        sys.exit(0)

    summarize_runs(args)

    