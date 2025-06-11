# 1000 iterations, on message "Hello, World!"

# RSDP 1 Balanced 
#Average KeyGen time: 88.77µs
#Average Sign time:   5.991978ms
#Average Verify time: 2.250335ms

# RSDP 1 SMALL
#Average KeyGen time: 91.354µs
#Average Sign time:   12.156164ms
#Average Verify time: 4.109059ms


# RSDP 1 FAST
#Average KeyGen time: 88.78µs
#Average Sign time:   3.380511ms
#Average Verify time: 1.764744ms


# C

# RSDP 1 BALANCED
#Average KeyGen time: 0.02 ms
#Average Sign time:   1.36 ms
#Average Verify time: 0.80 ms

#RSDP 1 SMALL
#Average KeyGen time: 0.02 ms
#Average Sign time:   2.71 ms
#Average Verify time: 1.65 ms

# RSDP 1 FAST
#Average KeyGen time: 0.02 ms
#Average Sign time:   0.74 ms
#Average Verify time: 0.44 ms

# C OPTIMIZED

# RSDP 1 BALANCED
# Average KeyGen time: 0.02 ms
# Average Sign time:   0.99 ms
# Average Verify time: 0.67 ms


#RSDP 1 SMALL
# Average KeyGen time: 0.02 ms
# Average Sign time:   1.98 ms
# Average Verify time: 1.39 ms

# RSDP 1 FAST
# Average KeyGen time: 0.02 ms
#Average Sign time:   0.51 ms
#Average Verify time: 0.32 ms

import matplotlib.pyplot as plt
import numpy as np

# Variants and operations
variants = ['Small', 'Balanced', 'Fast']
operations = ['KeyGen', 'Sign', 'Verify']

# X-axis labels
categories = [f"{v}_{op}" for v in variants for op in operations]

# Timing data in milliseconds
go_time = [
    0.091354, 12.156164, 4.109059,  # small
    0.08877, 5.991978, 2.250335,    # balanced
    0.08878, 3.380511, 1.764744     # fast
]

c_time = [
    0.02, 2.71, 1.65,   # small
    0.02, 1.36, 0.80,   # balanced
    0.02, 0.74, 0.44    # fast
]

c_opt_time = [
    0.02, 1.98, 1.39,   # small
    0.02, 0.99, 0.67,   # balanced
    0.02, 0.51, 0.32    # fast
]

# X-axis setup
x = np.arange(len(categories))
width = 0.25

# Plot setup
fig, ax = plt.subplots(figsize=(14, 6))

# Bars: adjust positions for 3 groups
bars1 = ax.bar(x - width,     go_time, width, label='Go', color='skyblue')
bars2 = ax.bar(x,             c_time, width, label='C (Reference)', color='lightgreen')
bars3 = ax.bar(x + width, c_opt_time, width, label='C (Optimized)', color='orange')

# Labels and styling
ax.set_yscale('log')
ax.set_ylabel('Time (ms)', fontsize=14)
ax.set_title('Runtime Comparison: Go vs C (Reference) vs C (Optimized) - (Small, Balanced, Fast)', fontsize=16)
ax.set_xticks(x)
ax.set_xticklabels([f"{v}\n{op}" for v in variants for op in operations], fontsize=12)
ax.tick_params(axis='y', labelsize=12)
ax.legend(fontsize=12)

# Annotate bars with values
def annotate_bars(bars, values):
    for bar, val in zip(bars, values):
        height = bar.get_height()
        ax.annotate(f'{val:.2f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)

annotate_bars(bars1, go_time)
annotate_bars(bars2, c_time)
annotate_bars(bars3, c_opt_time)

plt.tight_layout()
plt.show()
