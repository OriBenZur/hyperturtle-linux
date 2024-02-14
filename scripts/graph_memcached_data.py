import os
import numpy as np
import pandas as pd
from matplotlib import font_manager
import matplotlib.pyplot as plt

labels = {
    "double_virtio_L2": "Double Virtio",
    "direct_assignment_L2": "Direct Assignment",
    "direct_assignment_L2_packet_counter": "Direct Assignment w/ Packet Counter"
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
    
def plot_qps_latency(means, stds):
    '''
    @param means: a dictionary where the key is the QPS and the value is a dictionary where the key is the configuration and the value is the 99p latency
    @param stds: a dictionary where the key is the QPS and the value is a dictionary where the key is the configuration and the value is the standard deviation of the 99p latency
    '''
    markers = ['o', 'v', 's', 'p', 'P', '*', 'X', 'D', 'd', '1', '2', '3', '4', '8', 'h', 'H', '+', 'x', 'X', '|', '_']
    fig, ax = plt.subplots()
    index = 0
    for config, data in means.items():
        x = list(data.keys())
        y = list(data.values())
        ax.plot(x, y)
        ax.scatter(x, y, label=f'{labels[config]}', marker=markers[index])
        index += 1
    
    plt.axhline(y=500, color='black', linestyle='--')
    plt.text(4800, 502, 'SLA')  # Add text label slightly above the SLA line
    plt.ylabel('99p Latency [us]')
    plt.xlabel('Throughput [queries/sec]')    
    plt.gcf().set_size_inches(7, 4)  # Adjust the figure size for double column paper
    
    # Set the font to Times Roman
    # font_path = font_manager.findfont(font_manager.FontProperties(family='Times New Roman'))
    # font_manager.fontManager.addfont(font_path)
    # plt.rcParams['font.family'] = ['serif']
    # plt.rcParams['font.serif'] = ['Times New Roman']
    plt.ylim(bottom=0)
    
    plt.legend()
    plt.savefig('plot.png')
    plt.clf()


def process_string(string:str, array):
    words = string.split()
    if len(words) > 1 and words[0].strip(", ") == "read":
        array.append(float(words[-3].strip(", "))) # 99p latency
    return array


def get_99p_latencies_from_file(filename:str):
    '''
    @param filename: the name of the file to process
    @return: the mean and standard deviation of the 99p latencies, removing outliers that are more than 3 standard deviations away from the mean
    '''
    array = []
    with open(filename, 'r') as file:
        for line in file:
            array = process_string(line, array)
    
        array = np.array(array)
        mean = array.mean()
        std = array.std()
        new_array = array[abs(array - mean) <= 3 * std]
        if len(array) != len(new_array):
            print(f'removes {len(array) - len(new_array)} outliers')
        
    return new_array.mean(), new_array.std()


def build_latency_qps_dict(directory:str, qpss:list):
    '''
    @param directory: the directory to process
    @return: a dictionary where the key is the QPS and the value is a list of 99p latencies
    '''
    means = {qps:{} for qps in qpss}
    stds = {qps:{} for qps in qpss}
    for qps_dir in os.listdir(directory):
        if qps_dir.endswith("QPS"):
            for file in os.listdir(os.path.join(directory, qps_dir)):
                mean, std = get_99p_latencies_from_file(os.path.join(directory, qps_dir, file))
                qps = int(qps_dir[:-3])  # Remove the "QPS" suffix
                means[qps][file] = mean
                stds[qps][file] = std
    # for k, v in means.items():
    #     print(k, v)
    # for k, v in stds.items():
    #     print(k, v)
    return means, stds


# for qps in [1000, 2000]:
# plt.rcParams["font.family"] = "Times New Roman"
qpss = list(range(500, 5500, 500))
means, stds = build_latency_qps_dict("/mnt/bigdisk/ori/nestedTPT_measurements/results/memcached_qps_99p", qpss)
transposed_means = {file: {qps:means[qps][file] for qps in qpss} for file in means[qpss[0]]}
transposed_stds = {file: {qps:stds[qps][file] for qps in qpss} for file in stds[qpss[0]]}

plot_qps_latency(transposed_means, transposed_stds)



# for qps in [1000]:
#     name = f"memcached_{qps}qps_99p"
#     plot_average(f'/mnt/bigdisk/ori/nestedTPT_measurements/scripts/{name}.csv')


# for qps in [1000]:
#     name = f"memcached_{qps}qps_99p"
#     plot_average(f'/mnt/bigdisk/ori/nestedTPT_measurements/scripts/{name}.csv')

