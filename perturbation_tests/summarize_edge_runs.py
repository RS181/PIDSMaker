import pandas as pd
import pydoc
from tabulate import tabulate
import matplotlib.pyplot as plt
import argparse
import os
import sys
import re
import ast

SPLIT_VALS     = ["train","val","train_val","test"]
TARGET_VALS    = ["benign", "malicious", "all"]
SELECTION_VALS = ["random", "burst", "degree","betweenness", "event_type", "rarity"]
EDGE_RULE_VALS = ["src_node", "dst_node","both_nodes", "either_node"]
FRACTIONS_VALS = ["0.1", "0.3", "0.5", "0.7", "0.9"]

LOG_FOLDER = "./perturbation_tests/logs"

# Metric that are obtained from log files 
RESULT_DICT = {
    "run_args" : [],
    "nodes_total" : [],
    "nodes_malicious" : [],
    "nodes_benign" : [],
    "malicious_detected" : [],
    "malicious_undetected" : [],
    "tp" : [],
    "fp" : [],
    "tn" : [],
    "fn" : [],
    "precision" : [],
    "recall": [],
    "fpr" : [],
    "fscore" : [],
    "ap" : [],
    "accuracy" : [],
    "balanced_acc" : [],
    # "auc" : [],
    # "dor" : [],
    # "mcc" : [],

    # "ap" : [],
    # "ap" : [],
    # "fp_in_malicious_tw_ratio" : [],
    # "percent_detected_attacks" : [],
    # "fps_if_all_attacks_detected" : [],
    # "tps_if_all_attacks_detected" : [],
    # "precision_if_all_attacks_detected" : [],
    # "recall_if_all_attacks_detected" : [],
    "adp_score" : []
    # "threshold" : [],
    # "discrim_score_att_0" : [],
    # "discrim_score_att_1" : [],
    # "discrim_score_att_2" : [],
    # "discrimination" : [],
    # "discrim_tp_att_0" : [],
    # "discrim_tp_att_1" : [],
    # "discrim_tp_att_2" : [],
    # "discrim_tp_att_sum" : [],
    # "tp_att_0" : [],
    # "tp_att_1" : [],
    # "tp_att_2" : [],
    #"epoch" : [],

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

    #print(f"Filtrated {len(filtrated_runs)} from a total of {len(runs)}")
    #print(f"Filtrated using the following values  (not the keys):  {filtrate_vals} ")
    print(filtrate_vals)
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


def pretty_print_metrics():
    RESULT_DICT.pop("run_args")
    df = pd.DataFrame.from_dict(RESULT_DICT, orient='index').T
    # Ensure everything is fully expanded (no truncation)
    # Convert the DataFrame into a gorgeous terminal grid table
    # tablefmt options: 'fancy_grid', 'grid', 'pipe', 'psql'
    table_string = tabulate(
        df, 
        headers='keys', 
        #tablefmt='fancy_grid', # For visualization
        tablefmt='tsv', # To copy and paste to excel directly 
        showindex=True,
        # maxcolwidths=[30] # Optional: limits very wide text like run_args to 30 chars wide per cell, or remove it to see everything fully expanded
    )

    # Open it in the terminal pager so you can scroll up, down, left, and right (press 'q' to exit)
    print(table_string + "\n")



def summarize_runs(args):
    """
    Summarizes all .logs from a given:
    - dataset + model combination
    - filters given in args
    """
    args = clean_args(args)
    #print(f"Filters (values) that are going to be applied : {args}")
    #print(args)

    runs = os.listdir(f"{LOG_FOLDER}/{args['model']}-{args['dataset']}")
    filtered_runs = filtrate_runs(args,runs)

    if len(filtered_runs) == 0:
        print(f"No available runs after aplying given values in filter \n")
        sys,exit(0)


    for run in filtered_runs:
        if ".log" in run:
            get_and_store_args(args,run)
            get_and_store_results(args, run)


def build_runs_table(dataset: str, model: str, 
                     groupby_features : list[str], 
                     average_features : list[str],
                     count_features : list[str]) -> pd.DataFrame:
    """One row per run: run_args + metrics, plus model and dataset columns."""
    df = pd.DataFrame(RESULT_DICT)
    df['split']  = ""
    df['target'] = ""
    df['edge_rule'] = ""
    df['edge_types'] = ""
    df['fraction'] = ""
    df['selection'] = ""
    df['seed'] = ""
    df['model'] = model
    df['dataset'] = dataset

    # Iterate throuh each line df line and fill the values abobe with the values in run_args
    columns_to_fill = ['split','target','edge_rule','edge_types','fraction','selection','seed']

    for idx in df.index:
        run_args = ast.literal_eval(df.at[idx, "run_args"].strip())
        for c in columns_to_fill:
            df.at[idx, c] = run_args[c]
    df = df.drop(['run_args'], axis=1)
    # benign and all have no edge rule (None): give them a value, or groupby drops them
    df["edge_rule"] = df["edge_rule"].fillna("-")

    # pd.set_option('display.max_rows', None)
    # pd.set_option('display.max_columns', None)
    # pd.set_option('display.width', None)
    # pd.set_option('display.max_colwidth', None)
    # print(df)
    
    # Convert columns to int and float
    df[count_features] = df[count_features].astype(int)
    df[average_features] = df[average_features].astype(float)

    # Create groups and calculate mean/std results
    groups = df.groupby(groupby_features)

    #print(groups.size())
    # for name, group_df in groups:
    #     print(f"Group: {name}")
    #     print(group_df)

    # Calculate mean/std results
    stats = groups[average_features].agg(["mean","std"])
    stats.columns = [f"{metric}_{stat}" for metric, stat in stats.columns]
    stats["n_seeds"] = groups["seed"].count()

    # Calculate mean/std counts
    counts = groups[count_features].agg(["mean","std"])
    counts.columns = [f"{metric}_{stat}" for metric, stat in counts.columns]

    result_stats = stats.reset_index()
    result_counts = counts.reset_index()
    return result_stats, result_counts

def plot_metric(result, metric, title, out_path):
    fig, ax = plt.subplots(figsize=(6, 4))

    for (target, edge_rule), rows in result.groupby(["target", "edge_rule"]):
        rows = rows.sort_values("fraction")
        label = target if target != "malicious" else f"mal. {edge_rule}"
        mean = rows[f"{metric}_mean"]
        std = rows[f"{metric}_std"].fillna(0)

        ax.plot(rows["fraction"], mean, marker="o", label=label)
        ax.fill_between(rows["fraction"], mean - std, mean + std, alpha=0.15)

    ax.set_title(title)
    ax.set_xlabel("edge-removal fraction f")
    ax.set_ylabel(metric)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=3)
    fig.savefig(out_path, bbox_inches="tight")
    print(f"Saved fig in {out_path}")
    plt.close(fig)

def plot_all_metrics(result, metrics, title, out_path):
    fig, axes = plt.subplots(1, len(metrics), figsize=(4 * len(metrics), 3.5))

    for ax, metric in zip(axes, metrics):
        for (target, edge_rule), rows in result.groupby(["target", "edge_rule"]):
            rows = rows.sort_values("fraction")
            label = target if target != "malicious" else f"mal. {edge_rule}"
            mean = rows[f"{metric}_mean"]
            std = rows[f"{metric}_std"].fillna(0)

            ax.plot(rows["fraction"], mean, marker="o", label=label)
            ax.fill_between(rows["fraction"], mean - std, mean + std, alpha=0.15)

        ax.set_title(metric)
        ax.set_xlabel("edge-removal fraction f")

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.12), ncol=len(labels))
    fig.suptitle(title, y=1.18)

    fig.savefig(out_path, bbox_inches="tight")
    print(f"Saved fig in {out_path}")
    plt.close(fig)


def plot_all_metrics(result, metrics, title, out_path):
    fig, axes = plt.subplots(1, len(metrics), figsize=(4 * len(metrics), 3.5))

    for ax, metric in zip(axes, metrics):
        for (target, edge_rule), rows in result.groupby(["target", "edge_rule"]):
            rows = rows.sort_values("fraction")
            label = target if target != "malicious" else f"mal. {edge_rule}"
            mean = rows[f"{metric}_mean"]
            std = rows[f"{metric}_std"].fillna(0)

            ax.plot(rows["fraction"], mean, marker="o", label=label)
            ax.fill_between(rows["fraction"], mean - std, mean + std, alpha=0.15)

        ax.set_title(metric)
        ax.set_xlabel("edge-removal fraction f")

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.12), ncol=len(labels))
    fig.suptitle(title, y=1.18)

    fig.savefig(out_path, bbox_inches="tight")
    print(f"Saved fig in {out_path}")
    plt.close(fig)

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
    groupby_features = ['target', 'edge_rule', 'fraction'] # defines the features we use to group results (to later do the average and standard deviation)
    average_features = ['precision', 'recall', 'fpr', 'fscore', 'ap',
                     'accuracy', 'balanced_acc', 'adp_score'] # defines wich features we want the average/std from
    count_features = ['nodes_total', 'nodes_malicious', 'nodes_benign',
                    'malicious_detected', 'malicious_undetected',
                    'tp', 'fp', 'tn', 'fn']
    #test = [len(value) for value in RESULT_DICT.values()]
    #print(test)
    #print(RESULT_DICT)
    stats_metrics, stats_counts = build_runs_table(args.dataset, args.model, groupby_features, average_features, count_features)
    
    print(stats_metrics)
    print(stats_counts)


    # Uncoment code bellow to make individual graph
    #for metric in columns_to_plot:
    #    plot_metric(stats, metric, f"{args.model} - {args.dataset} [{metric}]", f"perturbation_tests/img/{args.model}_{args.dataset}_{metric}.png")
    
    plot_all_metrics(stats_metrics, average_features, f"{args.model} - {args.dataset}",f"perturbation_tests/img/{args.model}_{args.dataset}_metrics_all.png")
    plot_all_metrics(stats_counts, count_features, f"{args.model} - {args.dataset}",f"perturbation_tests/img/{args.model}_{args.dataset}_counts_all.png")

    #pretty_print_metrics()
    

    