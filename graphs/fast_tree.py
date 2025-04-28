import networkx as nx
import matplotlib.pyplot as plt

def hierarchy_pos(G, root=0, width=1.0, vert_gap=0.2, vert_loc=0, xcenter=0.5, pos=None, parent=None):
    if pos is None:
        pos = {root: (xcenter, vert_loc)}
    else:
        pos[root] = (xcenter, vert_loc)
    children = list(G.successors(root))
    if len(children) != 0:
        dx = width / len(children)
        nextx = xcenter - width/2 - dx/2
        for child in children:
            nextx += dx
            pos = hierarchy_pos(G, root=child, width=dx, vert_gap=vert_gap,
                                vert_loc=vert_loc - vert_gap, xcenter=nextx, pos=pos, parent=root)
    return pos

# Build the correct tree
G = nx.DiGraph()
edges = [
    (0,1), (0,2), (0,3), (0,4),
    (1,5), (1,6), (1,7),
    (2,8), (2,9),
    (3,10), (3,11),
    (4,12), (4,13)
]
G.add_edges_from(edges)

# Compute positions
pos = hierarchy_pos(G)

# Identify leaf and internal nodes
leaf_nodes = [n for n in G.nodes if G.out_degree(n) == 0]
internal_nodes = [n for n in G.nodes if G.out_degree(n) > 0]

# Draw nodes
nx.draw_networkx_nodes(G, pos, nodelist=internal_nodes, node_color="white", edgecolors="black", node_size=800)
nx.draw_networkx_nodes(G, pos, nodelist=leaf_nodes, node_color="white", edgecolors="black", node_size=800, linewidths=2, node_shape='o')

# Draw edges and labels
nx.draw_networkx_edges(G, pos)
nx.draw_networkx_labels(G, pos)

# Add '...' between leaf nodes
# Sort leaf nodes by x position
leaf_positions = sorted([(node, pos[node]) for node in leaf_nodes], key=lambda x: x[1][0])
#for (node1, (x1, y1)), (node2, (x2, y2)) in zip(leaf_positions[:-1], leaf_positions[1:]):
#    mid_x = (x1 + x2) / 2
#    mid_y = (y1 + y2) / 2
    #plt.text(mid_x, mid_y, '...', fontsize=12, ha='center', va='center')

# Finalize plot
plt.axis("off")
plt.tight_layout()
plt.savefig("fast_tree.png", dpi=300)



