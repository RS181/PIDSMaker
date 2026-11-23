import argparse
import subprocess


#SPLIT_VALS     = ["test"]
TARGET_VALS    = ["benign", "malicious", "all"]
#SELECTION_VALS = ["random"]
EDGE_RULE_VALS = ["src_node", "dst_node","both_nodes", "either_node"]
FRACTIONS_VALS = ["0.1", "0.3", "0.5", "0.7", "0.9"]



def summarize_results(args):
    dataset = args.dataset
    model = args.model
    print(f"Summarizing results for Model = {model} and Dataset = {dataset}")
    cmd = f"python perturbation_tests/summarize_edge_runs.py --dataset={dataset} --model={model} --selection=random --split=test"
 
    for f in FRACTIONS_VALS:
        for t in TARGET_VALS:
            for er in EDGE_RULE_VALS:
                subprocess.run(f"{cmd} --fraction={f} --target={t} --edge_rule={er}",shell=True)
                print(50 * "-")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=str, required=True, help="Choose the dataset")
    parser.add_argument("--model", type=str, required=True, help="Choose the model")

    args = parser.parse_args()

    summarize_results(args)
    