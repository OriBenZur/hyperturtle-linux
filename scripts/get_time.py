import os
import glob
import pandas as pd
import numpy as np
import csv
import re
import matplotlib.pyplot as plt
from typing import Callable

from decimal import Decimal

AVERAGE = "Average"
BEST = "Best"

y_labels = {
    "create processes" : "micro-seconds / process", "create threads" : "micro-seconds / thread", "demand-paging" : "seconds",
    "mprotect" : "mili-seconds", "mem alloc" : "ns", "launch programs" : "micro-seconds / program", "gups" : "seconds",
    "spawn" : "Processes / sec", "Percent of Cycles Page Walked" : "%", "Graph500" : "seconds"}
data_keys = [
    "Average", "Best",
    "mem_load_uops_retired.l1_miss:H", "mem_load_uops_retired.l2_miss:H", "mem_load_uops_retired.l3_miss:H",
    "mem_load_uops_retired.l1_hit:H", "mem_load_uops_retired.l2_hit:H", "mem_load_uops_retired.l3_hit:H", 
    "dtlb_load_misses.walk_duration:H", "dtlb_store_misses.walk_duration:H", "itlb_misses.walk_duration:H",
    "mem_load_uops_retired.l1_miss:G", "mem_load_uops_retired.l2_miss:G", "mem_load_uops_retired.l3_miss:G",
    "mem_load_uops_retired.l1_hit:G", "mem_load_uops_retired.l2_hit:G", "mem_load_uops_retired.l3_hit:G", 
    "dtlb_load_misses.walk_duration:G", "dtlb_store_misses.walk_duration:G", "itlb_misses.walk_duration:G",
    "ept.walk_cycles:H", "ept.walk_cycles:G", "cycles:G", "cycles:H"
    ]
alt_keys = [
    "mem_load_uops_retired.l1_miss", "mem_load_uops_retired.l2_miss", "mem_load_uops_retired.l3_miss",
    "mem_load_uops_retired.l1_hit", "mem_load_uops_retired.l2_hit", "mem_load_uops_retired.l3_hit",
    "mem_load_uops_retired.l1_try", "mem_load_uops_retired.l2_try", "mem_load_uops_retired.l3_try",
    "dtlb_load_misses.walk_duration", "dtlb_store_misses.walk_duration", "itlb_misses.walk_duration",
    "mem_load_uops_retired.l1_hit_rate", "mem_load_uops_retired.l2_hit_rate", "mem_load_uops_retired.l3_hit_rate",
    "ept.walk_cycles", "cycles"
    ]


def extract_data(file_path):
    '''
    Extract times from a results file.
    Returns a dictionary s.t. it's key is the result type (average, best, ...).
    If there's only one type if result, it's key is the empty string.
    '''
    data_dict = {}
    cur_key = ""
    data_dict[""] = []
    for key in data_keys:
        data_dict[key] = []
    for key in alt_keys:
        data_dict[key] = []
    instruction_g_count = 0
    instruction_h_count = 0
    n_g = 0
    n_h = 0
                
    with open(file_path, 'r') as f:
        for line in f:
            cur_key = ""
            for key in data_keys:
                if key in line:
                    cur_key = key
                    break

            if 's / ' in line:
                time = float(line.split()[1])
                data_dict[cur_key].append(time)
            elif 'pages took:' in line: # demand paging
                time = float(line.split()[4]) / 1000
                data_dict[cur_key].append(time)
            elif 'times took:' in line: # mprotect
                time = float(line.split()[5])
                data_dict[cur_key].append(time)
            elif 'seconds elapsed =' in line: # gups
                time = float(line.split()[-1])
                data_dict[cur_key].append(time)
            elif 'COUNT' in line: # spawn
                time = float(line.split('|')[1]) / 30
                data_dict[cur_key].append(time)
            elif 'Elapsed (wall clock) time (h:mm:ss or m:ss):' in line: # time -v
                wall_time = line.split()[-1].split(":")
                time = (float(wall_time[0]) * 60) + float(wall_time[1]) if len(wall_time) == 2 else (float(wall_time[0]) * 60 * 60) + (float(wall_time[1]) * 60) + float(wall_time[2])
                data_dict[cur_key].append(time)
            elif any([key in line for key in data_keys[2:]]): # perf
                time = float(line.split()[0].replace(",",""))
                data_dict[cur_key].append(time)

    #         elif "instructions:G" in line:
    #             instruction_h_count += int(line.split()[0].replace(",",""))
    #             n_g += 1
    #         elif "instructions:H" in line:
    #             instruction_h_count += int(line.split()[0].replace(",",""))
    #             n_h += 1

    # if n_g != 0: instruction_g_count /= n_g
    # if n_h != 0: instruction_h_count /= n_h

    if "trace" in file_path:
        for key in data_dict.keys():
            alt_key = key[:-2]
            if ":H" in key and len(data_dict[alt_key + ":G"]) > 0 and len(data_dict[alt_key + ":H"]) > 0:
                data_dict[alt_key] = [g_val + h_val for g_val, h_val in zip(data_dict[alt_key + ":G"], data_dict[alt_key + ":H"])]
        for key in data_dict.keys():
            if "mem_load_uops_retired" in key and "miss" in key and key in alt_keys:
                data_dict[key.replace("miss","try")] = [misses + hits for misses, hits in zip(data_dict[key], data_dict[key.replace("miss","hit")])]
                data_dict[key.replace("miss","hit_rate")] = [hits / total for hits, total in zip(data_dict[key.replace("miss","hit")], data_dict[key.replace("miss","try")])]
    #         if ":G" in key and instruction_h_count != 0:
    #             data_dict[key] = [1000000 * val / instruction_h_count for val in data_dict[key]]
    #         if ":H" in key and instruction_h_count != 0:
    #             data_dict[key] = [1000000 * val / instruction_h_count for val in data_dict[key]]
    data_dict["cycles"] = [data_dict["cycles"][i] for i in range(len(data_dict["cycles"])) if i % 2 == 0]
    data_dict["cycles:H"] = [data_dict["cycles:H"][i] for i in range(len(data_dict["cycles:H"])) if i % 2 == 0]
    data_dict["cycles:G"] = [data_dict["cycles:G"][i] for i in range(len(data_dict["cycles:G"])) if i % 2 == 0]
    data_dict["Percent of Cycles Page Walked"] = [100 * (store + load + itlb) / cyc for store, load, itlb, cyc in zip(data_dict["dtlb_load_misses.walk_duration"], data_dict["dtlb_store_misses.walk_duration"], data_dict["itlb_misses.walk_duration"], data_dict["cycles"])]
    return data_dict


def create_header(raw_name:str, results_type:str) -> str:
    '''
    Create a header for the results table from the file name.
    '''
    # header = re.split(r'1|2|3|4|5|6|7|8|9|0|_', raw_name)
    header = str(" ").join(raw_name.split("_")[0:-1],)
    if results_type != "":
        header = f'{header} ({results_type})'
    return header


def process_results(results_dir, process_if:Callable[[str], bool]=lambda x: True) -> pd.DataFrame:
    '''
    Process results from a directory.
    These results are from a single machine configuration.
    Returns a dataframe s.t. each column contains results from a different benchmarks. The column's header contains the name of the benchmark.
    '''
    results_dict = {}
    list_of_dirs = os.listdir(results_dir)
    for filename in list_of_dirs:
        if not process_if(os.path.basename(filename)):
            continue
        file_path = os.path.join(results_dir, filename)
        print(file_path)
        if os.path.isfile(file_path) and "warmup" not in file_path:
            times = extract_data(file_path)
            for key, val in times.items():
                if len(val) > 0:
                    print(filename, key, len(val))
                    # if len(val) != 16:
                        # continue
                    results_dict[create_header(filename, key)] = val[0:8]
    df = pd.DataFrame.from_dict(results_dict)
    df = df.reindex(sorted(df.columns), axis=1)
    return df


def get_title_from_str(title:str):
    '''
    Creates the appropriate title from the string given.
    '''
    if "gups" in title:
        title = "Random Access"
    elif "spawn" in title:
        title = "Spawn"
    elif "demand-paging" in title:
        title = "Demand Paging"
    return title

def measurement_type_to_name(measurement_type:str) -> str:
    return " ".join(measurement_type.split("_")[0:-1]).replace("ept", "NPT").replace("shadow", "Shadow")

def plot_charts(dfs_dict: dict[str, pd.DataFrame], ignore_groups: list[str] = []):
    filtered_cols = sorted([key for key in dfs_dict.keys() if key not in ignore_groups])
    # x_tick_labels = [s.capitalize() for s in x_tick_labels]
    y_label = "ERR!"
    plt.rcParams.update({'font.size': 14})
    plt.gcf().set_size_inches(9, 6)
    for column in dfs_dict[filtered_cols[1]].columns:
        measurments_for_loop = [key for key in filtered_cols if column in dfs_dict[key].columns]
        avgs = [np.mean(dfs_dict[key].loc[:,column]) for key in measurments_for_loop]
        vars = [np.std(dfs_dict[key].loc[:,column]) for key in measurments_for_loop]
        x = np.arange(len(avgs))
        x_tick_labels = sorted([measurement_type_to_name(key) for key in measurments_for_loop])
        bar = plt.bar(x, avgs, yerr=vars, tick_label=x_tick_labels)
        plt.xticks(rotation=25, ha='right', rotation_mode='anchor')
        title = get_title_from_str(" ".join(column.split(" ")[0:-2])) # if column == "Percent of Cycles Page Walked" else "Percent of Cycles Page Walked in Spawn"
        plt.subplots_adjust(bottom=0.2)
        # plt.title(title)
        plt.bar_label(bar, ["{:.2f}".format(avg) for avg in avgs])
        for key, val in y_labels.items():
            if key in column:
                y_label = val
                break
        
        plt.ylabel(y_label)
        plt.savefig(os.path.join("plots", column.replace(".","_")))
        plt.clf()

def plot_single_chart(dfs_dict: dict[str, pd.DataFrame]):
    filtered_cols = sorted([key for key in dfs_dict.keys()])
    legend_lables = sorted([(" ").join(key.split("_")[0:-1]).replace("ept", "NPT").replace("shadow", "Shadow") for key in dfs_dict.keys()])
    avgs = []
    all_errs = []
    len_prev = 0
    for i, column in enumerate(dfs_dict[list(dfs_dict.keys())[0]].columns):
        x = np.arange(len(filtered_cols) - 1)
        L0_key = None
        normalizer = np.mean(dfs_dict[L0_key].loc[:,column]) / 100 if (L0_key := next(key for key in dfs_dict.keys() if "L0" in key)) else 1
        avgs = [(np.mean(dfs_dict[key].loc[:,column]) / normalizer) - 100 for key in filtered_cols if "L0" not in key]
        vars = [(np.std(dfs_dict[key].loc[:,column]) / normalizer) for key in filtered_cols if "L0" not in key]
        
        bar = plt.bar(x + len_prev, avgs, yerr=vars)
        len_prev += len(avgs) + 1
    plt.xticks([1,2],["GUPS", "spawn"])
        # plt.xticks(rotation=25, ha='right', rotation_mode='anchor')
        # title = get_title_from_str(" ".join(column.split(" ")[0:-2])) # if column == "Percent of Cycles Page Walked" else "Percent of Cycles Page Walked in Spawn"
        # plt.subplots_adjust(bottom=0.2)
        # plt.title(title)
        # plt.bar_label(bar, ["{:.2f}".format(avg) for avg in avgs])
        # for key, val in y_labels.items():
        #     if key in column:
        #         y_label = val
        #         break
        
        # plt.ylabel(y_label)
    plt.savefig("fig_test")
        # plt.clf()
    return True


def main(results_pattern:str, process_if:Callable[[str], bool]=lambda x: True):
    dfs_dict = {}
    for results_dir in glob.glob(results_pattern):
        if not os.path.isdir(results_dir):
            continue
        df = process_results(results_dir, process_if)
        df.to_csv((os.path.basename(results_dir) + ".csv"), index=False, header=True)
        dfs_dict[os.path.basename(results_dir)] = df
    plot_charts(dfs_dict, ["L1_ept_on_ept_traces", "L1_shadow_on_ept_traces", "L1_shadow_on_shadow_traces", "L1_shadow_traces", "L2_shadow_on_ept_traces", "L2_shadow_on_shadow_traces"])
    # plot_single_chart(dfs_dict)

if __name__ == '__main__':
    try:
        os.mkdir("plots")
    except:
        print()
    results_benchmarks = []
    traces_benchmarks = []
    results_benchmarks = ["gups_PRE_HEATING", "spawn_PRE_HEATING", "demand-paging_COLD_START"]
    traces_benchmarks = ["spawn"]
    main("/home/ori/nestedTPTproject/nestedTPT_measurements/L*_results*", lambda x: any([val in x for val in results_benchmarks]))
    # main("/home/ori/nestedTPTproject/nestedTPT_measurements/L*_traces*", lambda x: any([x == val for val in traces_benchmarks]))
