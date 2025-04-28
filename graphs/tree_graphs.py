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

# Build the tree
G = nx.DiGraph()
edges = [(0,1),(0,2),(1,3),(1,4),(2,5),(2,6),
         (3,7),(3,8),(4,9),(4,10),(5,11),(5,12),
         (7,13),(7,14),(8,15),(8,16),(9,17),(9,18),(10,19),(10,20)]
G.add_edges_from(edges)

# Use Graphviz 'dot' layout with TB (top-bottom tree layout)
pos = hierarchy_pos(G)

# Find leaf and non-leaf nodes
leaf_nodes = [n for n in G.nodes if G.out_degree(n) == 0]
internal_nodes = [n for n in G.nodes if G.out_degree(n) > 0]

# Draw nodes: internal = gray, leaf = white
nx.draw_networkx_nodes(G, pos, nodelist=internal_nodes, node_color="lightgray", edgecolors="black", node_size=1200)
nx.draw_networkx_nodes(G, pos, nodelist=leaf_nodes, node_color="white", edgecolors="black", node_size=1200, linewidths=2)

# Draw edges and labels
nx.draw_networkx_edges(G, pos)
nx.draw_networkx_labels(G, pos)

# Aesthetics
plt.axis("off")
plt.tight_layout()
plt.savefig("balanced_tree.png", dpi=300)



