import os
import matplotlib.pyplot as plt


def get_netperf_latencies(file_path:str):
    """
    Parses a netperf latency file and returns a list of average latencies, p99 latencies, and standard deviations.
    """
    avg_latencies = {}
    p99_latencies = {}
    stds = {}
    cur_size = 0
    with open(file_path, 'r') as f:
        for line in f:
            line = line.replace(',', ' ')
            split_line = line.split(' ')
            if "throughput" in line:
                break
            if "size" in line:
                cur_size = int(split_line[-1])
                continue
            
            
            try:
                float(split_line[0])
            except ValueError:
                continue
            
            avg_latencies[cur_size] = float(split_line[0])
            p99_latencies[cur_size] = float(split_line[1])
            stds[cur_size] = float(split_line[2])
    return avg_latencies, p99_latencies, stds

colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k', 'w']
markers = ['o', 'v', 's', 'p', 'P', '*', 'X', 'D', 'd', '1', '2', '3', '4', '8', 'h', 'H', '+', 'x', 'X', '|', '_']


def plot_netperf_latencies(directory_path):
    """
    Reads netperf latency files in a directory and plots the latency figures.
    """
    file_paths = [os.path.join(directory_path, file) for file in os.listdir(directory_path) if file.endswith('.txt')]
    plt.figure()
    
    max_y = 0
    colors_idx = 0
    for file_path in file_paths:
        print(f'Plotting {file_path}')
        avg_latencies, p99_latencies, stds = get_netperf_latencies(file_path)
        sizes = list(avg_latencies.keys())
        avg_values = list(avg_latencies.values())
        p99_values = list(p99_latencies.values())
        std_values = list(stds.values())
        
        plt.errorbar(sizes, avg_values, yerr=std_values, label='Average Latency', color=colors[colors_idx], marker=markers[0])
        # plt.plot(sizes, avg_values, color=colors[colors_idx], marker=markers[0])
        plt.scatter(sizes, p99_values, label='P99 Latency', color=colors[colors_idx], marker=markers[1])
        plt.plot(sizes, p99_values, color=colors[colors_idx], marker=markers[1])
        # plt.plot(sizes, std_values, label='Standard Deviation')
        plt.xlabel('Size')
        plt.ylabel('Latency')
        plt.title(f'Netperf Latency Figure - {os.path.basename(file_path)}')
        max_y = max(max_y, max(p99_values))
        
        colors_idx += 1

    plt.ylim(bottom=0, top=max_y*1.1)
    plt.legend()
    plt.savefig("netperf.png")

if __name__ == '__main__':
    plot_netperf_latencies('/mnt/bigdisk/ori/nestedTPT_measurements/results/netperf/')