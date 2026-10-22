import os
import sys
import torch



def main(graph_path : str):
    """"""
    print(f"Loading original test graphs from {graph_path} ...")
    try:
        test_graphs = torch.load(graph_path, map_location="cpu")
    except Exception as e:
        sys.exit(f"Something went wrong! Error: {e}")
        


    print("Applying custom graph modifications...")
    # =========================================================
    # ADD YOUR CUSTOM FRAMEWORK / GRAPH ALTERATION LOGIC HERE
    # Example:
    # for graph in test_graphs:
    #     your_custom_transformation_function(graph)
    # =========================================================

    ##print("Saving modified test graphs...")
    ##with open(graph_path, "wb") as f:
    ##    pickle.dump(test_graphs, f)
    ##print("Successfully updated test graphs!")

def check_existance(path : str):
    """Check if path exists. Returns True if it exists and False otherwise"""
    if(not os.path.exists(path)):
        print(f"The following path doesnt exists: {path}")
        return False
    return True

if __name__ == "__main__":
    artifacts_dir = input("Indicate where the full path for artificats dir (e.g. /home/rui/projects/PIDSMaker/artifacts): ")
    
    if(not check_existance(artifacts_dir)):
        sys.exit(f"Error: Artifacts dir ({artifacts_dir}) doesnt exist.")

    print("\nIn the following path, to get the batching hash we want the corresponding HASH value:")
    print("/home/artifacts/batching/batching/<HASH>/<DATASET>/preprocessed_graphs/viz_test_graphs.pkl\n")
    batch_hash = input("Indicate the batching hash: ")
    
    print("\nList of available dataset values [provided by pidsmaker]:")
    print("CADETS_E3, THEIA_E3, CLEARSCOPE_E3, FIVEDIRECTIONS_E3, TRACE_E3, CADETS_E5, THEIA_E5, CLEARSCOPE_E5, FIVEDIRECTIONS_E5, TRACE_E5, OPTC_H2, OPTC_H_50, OPTC_H05, ATLASV2_EDR, CARBANAKV2_EDR\n")
    dataset_name = input("Indicate the dataset name: ")
    
    test_graph_path = f"{artifacts_dir}/batching/batching/{batch_hash}/{dataset_name}/preprocessed_graphs/viz_test_graphs.pkl"

    if(not check_existance(test_graph_path)):
        sys.exit(f"Error: Graph file was not found in {test_graph_path}")

    
    main(test_graph_path)
    