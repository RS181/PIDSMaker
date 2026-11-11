from datetime import datetime
from itertools import product
from concurrent.futures import ThreadPoolExecutor
import subprocess
import threading
import os
import shlex


## Number of workers
MAX_PARALLEL = 5  


## Model and Dataset constants
DATASET = "CADETS_E3"
MODEL = "flash"
LOGS_DIR = f"./perturbation_tests/logs/{MODEL}-{DATASET}"
STATUS_FILE = os.path.join(LOGS_DIR, "status.txt")


## Constants used to define the scenarios

# Wich split the perturbations are going to be applied
SPLITS = ["test"]

# Wich edges can be removed
TARGETS = ["benign","malicious","all"]

# Wich edges count as malicous (only works if TARGET=malicious)
EDGE_RULES = ["src_node", "dst_node","both_nodes", "either_node"]

# Wich type of edges are going to removed (if empty
# it will remove all types)
EDGE_TYPES = []

# Fraction of edges that is goign to be removed
FRACTIONS = [0.1, 0.3, 0.5, 0.7, 0.9]

# The strategy for choosing k = round(fraction × candidates) items among the eligible ones.
#SELECTIONS = ["random", "burst", "degree","betweenness", "event_type", "rarity"]
# TODO: for now only use random choosing strategy 
# TODO: Later try other cenarios ( I am trying first random
# to reduce number of total scenarios and to check initial
# results )
SELECTIONS = ["random"]

# Seeds used for randomness 
SEEDS = [12, 13 , 14]


# Possible cofigurations that are going to be tested (checks that 
# assures that the arguments combinations are valid are made bellow)
CONFIG = {
    "split"      : {"arg" : "--transformation.mal_perturbation.split", "vals" : SPLITS},
    "target"     : {"arg" : "--transformation.mal_perturbation.target", "vals" : TARGETS},
    "edge_rule"  : {"arg" : "--transformation.mal_perturbation.edge_rule", "vals" : EDGE_RULES},
    "edge_types" : {"arg" : "--transformation.mal_perturbation.edge_types", "vals" : EDGE_TYPES},
    "fraction"   : {"arg" : "--transformation.mal_perturbation.fraction", "vals" : FRACTIONS},
    "selection"  : {"arg" : "--transformation.mal_perturbation.selection", "vals" : SELECTIONS},
    "seed"       : {"arg" : "--transformation.mal_perturbation.seed", "vals" : SEEDS}
}

## Vars relating to thread execution 
processes = []           # every pipeline started (used to stop them on Ctrl+C)
lock = threading.Lock()  # protects processes, stopping and the status file
stopping = False         # True after Ctrl+C: no new pipelines start
_print_lock = threading.Lock()  # used only by log(), so lines from different threads never mix



## Functions that take care of threading and related stuff

def write_status(status: str, log_file: str, detail: str = ""):
    """
    Appends one line to STATUS_FILE: time | status | log file | detail.
 
    Args:
        status: "START", "DONE" or "FAIL".
        log_file: The scenario's log file (identifies the scenario).
        detail: Optional extra information, e.g. the exit code.
    """
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} | {status:<5} | {log_file} | {detail}\n"
    with lock:  # several threads write to this file
        with open(STATUS_FILE, "a") as f:
            f.write(line)

def load_done() -> set:
    """
    Returns the log files of the scenarios with a DONE line in STATUS_FILE.

    A scenario counts as completed only if it finished successfully: scenarios
    that failed, were interrupted, or never started have no DONE line.

    Returns:
        set of log file paths, e.g. {"./perturbation_tests/logs/magic-CADETS_E3/split_test_..."}
    """
    if not os.path.exists(STATUS_FILE):
        return set()
    done = set()
    with open(STATUS_FILE) as f:
        for line in f:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3 and parts[1] == "DONE":
                done.add(parts[2])
    return done

def run_command(cmd: str, log_file: str) -> int:
    """
    Runs cmd, appending everything it prints (output and errors) to log_file.
 
    Args:
        cmd: The full command as one string, e.g.
            "python pidsmaker/main.py magic CADETS_E3 --transformation.used_methods=..."
        log_file: Path of the log file, opened in append mode so the lines already
            written (scenario, command) stay at the top.
 
    Returns:
        The exit code: 0 = success, -1 = not started because the script is stopping,
        -15 = stopped by Ctrl+C, anything else = the pipeline failed.
    """
    with open(log_file, "a") as f, lock:
        if stopping:
            return -1
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}  # write to the log as it happens
        process = subprocess.Popen(shlex.split(cmd), stdout=f, stderr=subprocess.STDOUT, env=env)
        processes.append(process)
    return process.wait()

def stop_all():
    """
    Stops every running pipeline and prevents new ones from starting.
    """
    global stopping
    with lock:
        stopping = True
        for process in processes:
            process.terminate()  # does nothing for pipelines that already finished

def run_scenario(scenario: dict) -> bool:
    """
    Runs one scenario and records START / DONE / FAIL in STATUS_FILE.
 
    Args:
        scenario: One combination of parameters, as produced by all_scenarios().
 
    Returns:
        True if the pipeline finished successfully (or the scenario was skipped).
    """
    log_file = create_log_file(scenario)
 
    cmd = construct_command(scenario, include_viz_arg=False)
    write_to_log_file(log_file, scenario)
    write_to_log_file(log_file, cmd)
 
    log(f"START {log_file}")
    write_status("START", log_file)
 
    exit_code = run_command(cmd, log_file)
    ok = exit_code == 0
 
    log(f"{'DONE' if ok else 'FAIL'}  {log_file}")
    write_status("DONE" if ok else "FAIL", log_file, f"exit code {exit_code}")
    return ok


## Function to construct commands

def construct_command(scenario: dict, include_viz_arg: bool) -> str:
    # base command 
    base = f"python pidsmaker/main.py {MODEL} {DATASET} --transformation.used_methods=mal_perturbation --transformation.mal_perturbation.operation=remove_edges"     
    arguments = ""
    wandb_args =f"{DATASET}-{MODEL}-"
    viz_arg = "--save_for_viz" if include_viz_arg else ""
    
    for k, v in scenario.items(): 
        if v is None:
            continue
        arg = CONFIG[k]["arg"]
        arguments += f"{arg}={v} " 
        wandb_args += f"{k}_{v}-"

    # Removed --wand and arguments because it had connection errors 
    #return f"{base} {arguments} {viz_arg} --wandb --exp={wandb_args} --tags={MODEL}-{DATASET}" 
    return f"{base} {arguments} {viz_arg}"


## Logging related functions

def log(msg: str, return_line=False, pre_return_line=False, *args, **kwargs):
    with _print_lock:
        if pre_return_line:
            print("")

        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - {msg}", *args, **kwargs)

        if return_line:
            print("")
        return f"{timestamp} - {msg}"

def log_file_path(scenario: dict) -> str:
    """The log file path of a scenario: always the same for the same scenario."""
    name = "_".join(f"{k}-{v}" for k, v in scenario.items() if v is not None)
    return os.path.join(LOGS_DIR, name + ".log")


def create_log_file(scenario: dict) -> str:
    """Creates (or empties) the scenario's log file and returns its path."""
    path = log_file_path(scenario)
    open(path, "w").close()  # "w": a rerun of a failed scenario starts a fresh log
    return path

def write_to_log_file(log_file : str, msg):
    with open(log_file, "a") as f:
        f.write(log(msg) + "\n") 
    

## Functions to build and validate scenarios 

def is_valid(scenario: dict) -> bool:
    """False for combinations that make no sense."""
    # Training and validation graphs contain no attack: nothing malicious to remove
    if scenario["split"] != "test" and scenario["target"] == "malicious":
        return False
    return True


def normalize(scenario: dict) -> dict:
    """Sets unused parameters to None, so equivalent scenarios become identical."""
    if scenario["target"] != "malicious":
        scenario["edge_rule"] = None  # edge_rule is ignored unless target=malicious
    return scenario


def all_scenarios():
    """Yields every valid scenario: one dict per combination of CONFIG values."""
    names = list(CONFIG)
    # An empty list would make product() return nothing, so use [None] ("not set") instead
    value_lists = [CONFIG[name]["vals"] or [None] for name in names]

    seen = set()
    for values in product(*value_lists):
        scenario = normalize(dict(zip(names, values)))
        if not is_valid(scenario):
            continue
        key = tuple(scenario.items())
        if key in seen:  # already produced (e.g. same scenario with another edge_rule)
            continue
        seen.add(key)
        yield scenario

## Main entry point

if __name__ == "__main__":
    """
    IMPORTANT NOTE, for each DATASET, we need to run the pipeline until it finishes
    the construction phase at least once, using just one thread (to ensure we 
    only do the CONSTRUCTION phase once)
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    all_scenarios = list(all_scenarios())
    done = load_done()
    scenarios = [s for s in all_scenarios if log_file_path(s) not in done]
    log(f"Total scenarios: {len(all_scenarios)} | already done: {len(all_scenarios) - len(scenarios)} "
        f"| to run: {len(scenarios)}")

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        try:
            results = list(pool.map(run_scenario, scenarios))
        except KeyboardInterrupt:
            log("Ctrl+C: stopping all pipelines...")
            stop_all()
            pool.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(1)
 
    log(f"Finished: {sum(results)} succeeded, {len(results) - sum(results)} failed")
    log(f"Status of every scenario: {STATUS_FILE}")
