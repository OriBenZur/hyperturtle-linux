import os
import numpy as np
import pandas as pd
from matplotlib import font_manager
import matplotlib.pyplot as plt

labels = {
    "double_virtio_L2": "Double Virtio",
    "direct_assignment_L2": "Direct Assignment",
    "direct_assignment_L2_packet_counter": "Direct Assignment w/ Packet Counter",
    "double_virtio_L2_1vcpus_1workers_1vhost": "Double Virtio - 1 vCPUs;1 vhost",
    "double_virtio_L2_3vcpus_3workers_1vhost": "Double Virtio - 3 vCPUs;1 vhost",
    "double_virtio_L2_4vcpus_4workers_2vhost": "Double Virtio - 4 vCPUs;2 vhost",
    "direct_assignment_L2_1vcpus_1workers_1vhost": "Direct Assignment - 1 vCPUs;1 vhost",
    "direct_assignment_L2_3vcpus_3workers_1vhost": "Direct Assignment - 3 vCPUs;1 vhost",
    "direct_assignment_L2_4vcpus_4workers_1vhost": "Direct Assignment - 4 vCPUs;1 vhost",
    "direct_assignment_L2_3vcpus_3workers_2vhost": "Direct Assignment - 3 vCPUs;2 vhost",
    "direct_assignment_L2_4vcpus_4workers_2vhost": "Direct Assignment - 4 vCPUs;2 vhost",
    "direct_assignment_L2_5vcpus_5workers_3vhost": "Direct Assignment - 5 vCPUs;3 vhost",
    "direct_assignment_L2_6vcpus_6workers_2vhost": "Direct Assignment - 6 vCPUs;2 vhost",
    }

def plot_average(filename):
    df = pd.read_csv(filename)
    n_data_cols = len(df.columns) - 2
    print(df.mean())
    print(df.std())
    print(df.std()/df.mean())
    filtered_df = pd.DataFrame()
    # remove outliers: values that are more than 4 standard deviations away from the mean
    for column in df.columns:
        # Calculate mean and standard deviation for the current column
        col_mean = df[column].mean()
        col_std = df[column].std()

        # Filter values within the specified threshold
        filtered_values = df[column][abs(df[column] - col_mean) <= 3 * col_std]

        # Add the filtered values to the new DataFrame
        filtered_df[column] = filtered_values
    print(df)
    print(filtered_df)
    return
    ax = df.mean().plot(kind='bar', yerr=df.std())  # Plot with error bars
    plt.ylabel('Average')
    plt.xticks(rotation=8)
    
    for i, (v, var) in enumerate(zip(df.mean(), df.std())):
        ax.text(i, v, str(round(v, 2)), ha='center', va='bottom')
        # ax.text(i, v + var, str(round(var, 2)), ha='center', va='top', color='red')
    
    plt.gcf().set_size_inches(10, 6)  # Adjust the figure size
    
    plt.savefig(f'{os.path.basename(filename)}.png')
    plt.clf() 
    
    # Normalize the values to the lowest value
    norm = df.mean()[0]
    normalized_averages = df.mean() / norm
    ax_normalized = normalized_averages.plot(kind='bar')
    plt.ylabel('Normalized Average')
    plt.xticks(rotation=8)  # Rotate the x-axis labels by 45 degrees
    
    for i, v in enumerate(normalized_averages):
        ax_normalized.text(i, v, str(round(v, 2)), ha='center', va='bottom')

    plt.gcf().set_size_inches(10, 6)  # Adjust the figure size
    
    plt.savefig(f'{os.path.basename(filename)}_normalized.png')
    plt.clf()
    
def plot_qps_latency(means, stds, plot_name):
    '''
    @param means: a dictionary where the key is the QPS and the value is a dictionary where the key is the configuration and the value is the 99p latency
    @param stds: a dictionary where the key is the QPS and the value is a dictionary where the key is the configuration and the value is the standard deviation of the 99p latency
    '''
    markers = ['o', 'v', 's', 'p', 'P', '*', 'X', 'D', 'd', '1', '2', '3', '4', '8', 'h', 'H', '+', 'x', 'X', '|', '_']
    color = ['b', 'g', 'r', 'c', 'm']
    fig, ax = plt.subplots()
    index = 0
    max_y = 0
    max_x = 0
    for config, data in sorted(means.items()):
        data = {k:data[k] for k in sorted(data.keys())}
        x = list(data.keys())
        y = list(data.values())
        max_y = max(max_y, max(y))
        # this_max = max(x[1:])
        max_x = max(max_x, max(x))
        ax.plot(x, y, linewidth=1, color=color[index % len(color)])
        label = labels[config] if config in labels.keys() else config
        ax.scatter(x, y, label=f'{label}', marker=markers[index % len(markers)], color=color[index % len(color)])
        index += 1
    
    max_x = min(max_x*1.1, 150000)
    left, right = plt.xlim(left=0, right=max_x*1.1)
    
    # left, right = plt.xlim()
    plt.ylim(bottom=0)
    max_y = min(max_y*1.2, 1800)
    top, bottom = plt.ylim(bottom=0, top=max_y)
    # if "single_vhost" in plot_name or "multiple_vhost" in plot_name:
    #     top, bottom = plt.ylim(bottom=0, top=1200)
    # top, bottom = plt.ylim(bottom=0)
    plt.axhline(y=500, color='black', linestyle='--')
    plt.text(right*0.8, 520, '500us SLA')  # Add text label slightly above the SLA line
    plt.axhline(y=1000, color='black', linestyle='--')
    plt.text(right*0.8, 1020, '1000us SLA')  # Add text label slightly above the SLA line
    plt.ylabel('99p Latency [us]')
    plt.xlabel('Throughput [queries/sec]')    
    # plt.gcf().set_size_inches(7, 4)  # Adjust the figure size for double column paper
    plt.gcf().set_size_inches(14, 8)  # Adjust the figure size for double column paper
    # Set the font to Times Roman
    # font_path = font_manager.findfont(font_manager.FontProperties(family='Times New Roman'))
    # font_manager.fontManager.addfont(font_path)
    # plt.rcParams['font.family'] = ['serif']
    # plt.rcParams['font.serif'] = ['Times New Roman']
    plt.ylim(bottom=0)

    plt.legend()
    plt.savefig(f'{plot_name}.png')
    print(f'saved {plot_name}.png')
    plt.clf()


def get_99p_latency_from_string(string:str, array):
    words = string.split()
    if len(words) > 1 and words[0].strip(", ") == "read":
        # array.append(float(words[1].strip(", "))) # avg latency
        array.append(float(words[-1].strip(", "))) # 99p latency
    return array

def get_qps_from_string(string:str, array):
    words = string.split()
    if len(words) > 1 and words[1].strip(", ") == "QPS":
        array.append(float(words[3].strip(", ")))
    return array


def get_99p_latencies_from_file(filename:str):
    '''
    @param filename: the name of the file to process
    @return: the mean and standard deviation of the 99p latencies, removing outliers that are more than 3 standard deviations away from the mean
    '''
    latency_array = []
    qps_array = []
    with open(filename, 'r') as file:
        for line in file:
            latency_array = get_99p_latency_from_string(line, latency_array)
            qps_array = get_qps_from_string(line, qps_array)
        latency_array = np.array(latency_array)
        qps = np.array(qps_array).mean()
        mean = latency_array.mean()
        std = latency_array.std()
        new_array = latency_array[abs(latency_array - mean) <= 3 * std]
        if len(latency_array) != len(new_array):
            print(f'filename: {filename}: removed {len(latency_array) - len(new_array)} outliers')
        
    return new_array.mean(), new_array.std(), qps


def build_latency_qps_dict(directory:str, qpss:list, filter=None):
    '''
    @param directory: the directory to process
    @return: a dictionary where the key is the QPS and the value is a list of 99p latencies
    '''
    max_std = 0
    means = {}
    stds = {}
    # means = {qps:{} for qps in qpss}
    # stds = {qps:{} for qps in qpss}
    # for qps_dir in os.listdir(directory):
    for qps in sorted(qpss):
        # if qps_dir.endswith("QPS"):
        qps_dir = f'{qps}QPS'
        configs = os.listdir(os.path.join(directory, qps_dir))
        for file in configs:
            if filter is not None and all(element not in file for element in filter):
            # if "double_virtio_L2_4vcpus_4workers_2vhost" not in file and "direct_assignment_L2_4vcpus_4workers_2vhost" not in file and "direct_assignment_L2_6vcpus_6workers_2vhost" not in file and "direct_assignment_L2_5vcpus_5workers_3vhost" not in file:
                continue
            mean, std, mean_qps = get_99p_latencies_from_file(os.path.join(directory, qps_dir, file))
            if (std/mean) > 0.15:
                print(f'{file},{qps},{mean_qps} has high std/mean ratio: {std/mean}')
            max_std = max(std/mean, max_std)
            file = file.replace(".new", "")
            # qps = int(qps_dir[:-3])  # Remove the "QPS" suffix
            if file not in means.keys():
                means[file] = {}
                stds[file] = {}
            means[file][mean_qps] = mean
            stds[file][mean_qps] = std
    # for k, v in means.items():
    #     print(k, v)
    # for k, v in stds.items():
    #     print(k, v)
    print(f'max_std: {max_std}')
    return means, stds


# for qps in [1000, 2000]:
# plt.rcParams["font.family"] = "Times New Roman"
qpss = list(range(7500, 20500, 1000))
directory = "/home/ori/results/memcached.direct_connection.new"
dir_qpss = sorted([int(qps[:-3]) for qps in os.listdir(directory) if int(qps[:-3]) > 0])

# filter_442 = ["double_virtio_L2_3vcpus_3workers_2vhost", "double_virtio_L2_4vcpus_4workers_2vhost", "direct_assignment_L2_3vcpus_3workers_2vhost", "direct_assignment_L2_4vcpus_4workers_2vhost", "direct_assignment_L2_5vcpus_5workers_2vhost", "direct_assignment_L2_6vcpus_6workers_2vhost", "direct_assignment_L2_5vcpus_5workers_3vhost", "direct_assignment_L2_6vcpus_6workers_3vhost"]
# filter_442 = ["double_virtio_L2_4vcpus_4workers_2vhost", "direct_assignment_L2_4vcpus_4workers_2vhost", "direct_assignment_L2_6vcpus_6workers_2vhost", "direct_assignment_L2_5vcpus_5workers_3vhost"]
# means, stds = build_latency_qps_dict(directory, dir_qpss, filter_442)
# qpss = sorted(means.keys())
# # transposed_means = {file: {qps:means[qps][file] for qps in qpss if qps in means.keys() and file in means[qps].keys()} for file in means[qpss[0]]}
# # transposed_stds = {file: {qps:stds[qps][file] for qps in qpss if qps in means.keys() and file in means[qps].keys()} for file in stds[qpss[0]]}
# plot_qps_latency(means, stds, "memcached_99p_latency_multiple_vhost")

# filter_441= ["double_virtio_L2_3vcpus_3workers_1vhost", "direct_assignment_L2_3vcpus_3workers_1vhost", "direct_assignment_L2_4vcpus_4workers_1vhost", "direct_assignment_L2_3vcpus_3workers_2vhost"]
# means, stds = build_latency_qps_dict(directory, dir_qpss, filter_441)
# qpss = sorted(means.keys())
# # means = {file: {qps:means[qps][file] for qps in qpss if qps in means.keys() and file in means[qps].keys()} for file in means[qpss[0]]}
# # stds = {file: {qps:stds[qps][file] for qps in qpss if qps in means.keys() and file in means[qps].keys()} for file in stds[qpss[0]]}
# plot_qps_latency(means, stds, "memcached_99p_latency_single_vhost")

# filter_441= ["1vcpus_1workers_1vhost"]
# means, stds = build_latency_qps_dict(directory, dir_qpss, filter_441)
# qpss = sorted(means.keys())
# plot_qps_latency(means, stds, "memcached_99p_latency_single_vcpu")

# filter_441= ["4vcpus_1workers_1vhost"]
# means, stds = build_latency_qps_dict(directory, dir_qpss, filter_441)
# qpss = sorted(means.keys())
# plot_qps_latency(means, stds, "memcached_99p_latency_single_worker")

filter_441= ["4vcpus_4workers_1vhost"]
means, stds = build_latency_qps_dict(directory, dir_qpss, filter_441)
qpss = sorted(means.keys())
plot_qps_latency(means, stds, "memcached_99p_latency_four_workers")

# for qps in [1000]:
#     name = f"memcached_{qps}qps_99p"
#     plot_average(f'/mnt/bigdisk/ori/nestedTPT_measurements/scripts/{name}.csv')


# for qps in [1000]:
#     name = f"memcached_{qps}qps_99p"
#     plot_average(f'/mnt/bigdisk/ori/nestedTPT_measurements/scripts/{name}.csv')

