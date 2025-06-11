

# go_keygen_balanced = 14064
# go_sign_balanced = 1485124
# go_verify_balanced = 643564

# c_keygen_balanced = 8064
# c_sign_balanced = 96112
# c_verify_balanced = 209536


# go_keygen_small = 14126
# go_sign_small = 3012461
# go_verify_small = 1317094

# c_keygen_small = 8064
# c_sign_small = 420256
# c_verify_small = 189328


# go_keygen_fast = 14094
# go_sign_fast = 748027
# go_verify_fast = 339601

# c_keygen_fast = 8064
# c_sign_fast = 115552
# c_verify_fast = 56144



import matplotlib.pyplot as plt
import numpy as np

# Labels
variants = [ 'balanced']
operations = ['keygen', 'sign', 'verify']

# Flattened X-axis categories
categories = [f"{v}_{op}" for v in variants for op in operations]

# Memory usage data (Go and C)
go_mem = [
    14064, 1485124, 643564,   # balanced
]
c_mem = [
    8064, 209536, 96112,      # balanced
]

# Convert to KB for readability
go_mem_kb = [v / 1024 for v in go_mem]
c_mem_kb = [v / 1024 for v in c_mem]

# X-axis setup
x = np.arange(len(categories))
width = 0.35

# Plot
fig, ax = plt.subplots(figsize=(12, 6))
bars1 = ax.bar(x - width/2, go_mem_kb, width, label='Go', color='skyblue')
bars2 = ax.bar(x + width/2, c_mem_kb, width, label='C', color='lightgreen')

# Labels and styling
ax.set_yscale('log')
ax.set_ylabel('Memory Usage (KB)')
ax.set_title('Memory Usage Comparison: Go vs C (small, balanced, fast)')
ax.set_xticks(x)
ax.set_xticklabels([f"{v}\n{op}" for v in variants for op in operations])
ax.legend()

# Optional: annotate bars with exact values
def annotate_bars(bars, values):
    for bar, val in zip(bars, values):
        height = bar.get_height()
        ax.annotate(f'{val:.0f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=14)

annotate_bars(bars1, go_mem_kb)
annotate_bars(bars2, c_mem_kb)

plt.tight_layout()
plt.show()