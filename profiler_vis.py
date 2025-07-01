# Imports for ,etric visualization
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import os

folder = "profiler_output"
os.makedirs(folder, exist_ok=True)

df = pd.read_csv("profiling_data.csv")

# filter dataframe to only include entries with latency below a certain threshold
threshold = 6000 
df_filtered = df[df['latency'] <= threshold].copy()

# Datafram for memory accesses and migration
mem_access = df_filtered[df_filtered['type'].isin([2,3])].copy()
migration = df_filtered[df_filtered['type'] == 1].copy()

# create new coloum for access locality
mem_access['access_type'] = mem_access.apply(lambda row: "local" if row['thread_nid'] == row['folio_nid'] else "remote", axis = 1)

# get max and min time to depict normalized time
hist_heat_min_time = mem_access["time"].min()
hist_heat_max_time = mem_access["time"].max()

# application wide Metrics
fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(12,4.5))

# create histogram for remote/local accesses
sns.histplot(data=mem_access, x=(mem_access['time'] - hist_heat_min_time) / (hist_heat_max_time - hist_heat_min_time), hue='access_type', multiple='stack', bins=100, ax=ax1)
ax1.set_title("Remote and Local accesses")
ax1.set_xlabel('Time')
ax1.set_ylabel('Count')

# create heatmap for Node Imbalance
heatmap_data = mem_access.pivot_table(index='thread_nid', columns='folio_nid', values='nr', aggfunc='count')
sns.heatmap(heatmap_data, annot=True, fmt='.0f', cmap='Reds', cbar=False, ax=ax2)
ax2.set_title("Node Imbalance")
ax2.set_ylabel("Task NUMA Node")
ax2.set_xlabel("Folio NUMA Node")

reg_sample = min(len(mem_access), 1000)
reg_plot_filtered = mem_access[mem_access['type'] == 2].sample(reg_sample)
reg_plot = reg_plot_filtered.sample(reg_sample)

sns.regplot(data=reg_plot, x=(reg_plot['time'] - hist_heat_min_time) / (hist_heat_max_time - hist_heat_min_time), y='latency', scatter_kws={"alpha":0.15}, ax=ax3)
ax3.set_title("Latency Distribution")
ax3.set_ylabel("Latency (ns)")
ax3.set_xlabel("Time")

# store and close created plot
plt.tight_layout()
plt.savefig(os.path.join(folder, "Application_profile.png"))
plt.close()


palette = sns.color_palette("rocket_r", as_cmap=True)

# Per-task metric visualization

# get thread ids to iterate over 
thread_ids = df_filtered['thread_id'].unique()

# get NUMA nodes
folio_nodes = df_filtered['folio_nid'].unique()
thread_nodes = df_filtered['thread_nid'].unique()
nodes = list(set(list(folio_nodes) + list(thread_nodes)))

palette = sns.color_palette("tab10", n_colors=len(nodes))
color_map = {cat: palette[i] for i, cat in enumerate(nodes)}

blue = sns.color_palette("crest", as_cmap=True)

# Start the per-task metric visualization
for tid in thread_ids:
    
    # Get the memory per thread
    thread_mem = mem_access[mem_access['thread_id'] == tid].copy() # Use sample to limit the number of  folio
    sample_size = min(len(thread_mem), 1000)
    thread_mem_sample = thread_mem.sample(sample_size)
    # We are not interested in threads that did not access memory
    if thread_mem.empty:
        continue
    
    else:

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16,8))

        # This is mainly used for the thread scheduling in regard to access locality, making the plot a lot cleaner
        thread_data = df_filtered[df_filtered['thread_id'] == tid].copy()
        min_time = thread_data["time"].min()
        max_time = thread_data["time"].max()
        
        # Automatic NUMA balancing events have no latency, omit them
        thread_mem_rw = thread_mem_sample[thread_mem_sample['type'] == 2].copy()

        sns.scatterplot(data=thread_mem_rw, x=((thread_mem_rw['time'] - min_time) / (max_time - min_time)), y='latency',
                         hue="folio_nid", palette=color_map, style='access_type', size='nr', alpha=0.4, style_order=["local", "remote"], markers=['o', 'X'], ax=ax1)
                                                    

        thread_migration = migration[migration["thread_id"] == tid].copy()
        thread_migration['time_norm'] = (thread_migration["time"] - min_time) / (max_time - min_time)
        thread_mem_sample['time_norm'] = (thread_mem["time"] - min_time) / (max_time - min_time)
        thread_data['time_norm'] = (thread_data["time"] - min_time) / (max_time - min_time)

        for _, row in thread_migration.iterrows():
            ax1.axvline(x=row["time_norm"], linestyle=':', color=color_map[row['thread_nid']], label=f"Switch: NID {row['thread_nid']}", alpha=0.8)
        legend = ax1.get_legend()
        for text in legend.get_texts():
            if text.get_text() == 'folio_nid':
                text.set_text('Node ID')
            if text.get_text() == 'nr':
                text.set_text('Pages')
            if text.get_text() == 'access_type':
                text.set_text('Location')
        ax1.set_title(f"Scheduling and latency of Task = {tid}")
        ax1.set_xlabel("Time")
        ax1.set_ylabel("Latency (ns)")


        sns.lineplot(data=thread_data, x="time_norm", y="thread_nid", drawstyle='steps-post', ax=ax2)
        sns.scatterplot(data=thread_mem_sample, x='time_norm', y='folio_nid', size='nr', ax=ax2) 


        plt.yticks(nodes)
        ax2.set_title(f"Scheduling and access pattern of Task = {tid}")
        ax2.set_xlabel("Time")
        ax2.set_ylabel("NUMA node ID")
                
        plt.tight_layout()
        plt.savefig(os.path.join(folder, f"Task_{tid}.png"))
        plt.close()
